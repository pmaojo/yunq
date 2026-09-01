//! Shannon-entropy scoring for string literals that look like random
//! tokens/keys even when they don't match any known provider signature.
//! This is the generic net that catches private/self-hosted service tokens,
//! newly-issued provider formats we haven't special-cased yet, and one-off
//! random secrets.

use std::collections::HashMap;

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Shannon entropy of `s`, in bits per character, computed from the
/// character-frequency distribution within `s` itself (not a fixed
/// alphabet). Empty input has zero entropy.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    let mut len: u32 = 0;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
        len += 1;
    }
    let len = f64::from(len);
    freq.values().fold(0.0, |acc, &count| {
        let p = f64::from(count) / len;
        acc - p * p.log2()
    })
}

/// Resolves the handful of common backslash escapes (`\n`, `\t`, `\r`,
/// `\\`, `\"`, `\'`, `\0`) to their actual character, leaving anything else
/// untouched. A literal like `"rule_id,severity,message\n"` reads as a
/// comma-joined header row followed by a real newline once unescaped —
/// exactly the shape the whitespace/charset checks below already know how
/// to recognize as non-secret — rather than a string ending in a stray `\`
/// symbol byte.
fn unescape_common(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(&esc @ ('\\' | '"' | '\'')) => out.push(esc),
            _ => {
                out.push(c);
                continue;
            }
        }
        chars.next();
    }
    out
}

/// Strips one layer of matching quote characters (`"`, `'`, `` ` ``) so
/// entropy is computed over the literal's value, not its syntax. Also
/// drops a Rust byte/raw-string prefix (`b"..."`, `r"..."`, `br"..."`,
/// `rb"..."`) first — those aren't part of the value either, and left in
/// place they'd make an exact-match check like
/// [`looks_like_known_charset_alphabet`] never fire on the byte-string
/// constants that's the common way to declare a fixed alphabet.
fn strip_quotes(s: &str) -> &str {
    let s = s
        .strip_prefix("br")
        .or_else(|| s.strip_prefix("rb"))
        .or_else(|| s.strip_prefix('b'))
        .or_else(|| s.strip_prefix('r'))
        .unwrap_or(s);
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && matches!(first, b'"' | b'\'' | b'`') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Common hex digest lengths (MD5, SHA-1, SHA-224/256, SHA-384, SHA-512) —
/// high entropy but almost always a checksum or git commit SHA, not a
/// secret.
fn looks_like_hex_digest(s: &str) -> bool {
    s.len() >= 8
        && matches!(s.len(), 32 | 40 | 56 | 64 | 96 | 128)
        && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// RFC 4122 UUID shape (`8-4-4-4-12` hex groups) — a common non-secret
/// identifier that happens to have high entropy.
fn looks_like_uuid(s: &str) -> bool {
    let expected_lengths = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == expected_lengths.len()
        && parts
            .iter()
            .zip(expected_lengths)
            .all(|(part, len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// CSS variables (`var(--...)`) can have high entropy but are not secrets.
fn looks_like_css_variable(s: &str) -> bool {
    s.starts_with("var(--") && s.ends_with(')')
}

/// The handful of well-known fixed alphabets a hand-rolled encoder/decoder
/// declares as a constant (`const ALPHABET: &[u8] = b"ABC...";`). These are
/// deliberately high-entropy — that's the whole point of an alphabet meant
/// to cover the input's character space evenly — but they're publicly
/// documented constants, not a private value.
fn looks_like_known_charset_alphabet(s: &str) -> bool {
    const KNOWN_ALPHABETS: &[&str] = &[
        // Base64 standard and URL-safe.
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        // Base32 (RFC 4648) and z-base-32.
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "ybndrfg8ejkmcpqxot1uwisza345h769",
        // Base58 (Bitcoin/IPFS).
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        // Base62.
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ];
    KNOWN_ALPHABETS.contains(&s)
}

/// Tailwind's arbitrary-value/arbitrary-variant syntax packs a CSS selector
/// or value straight into square brackets inside the class name itself —
/// `[&_tr:last-child]:border-0`, `top-[calc(-50%_-_2px)]`,
/// `grid-cols-[repeat(auto-fill,minmax(120px,1fr))]`. The `&`, `(`, `)`,
/// `%`, `,`, `=` characters that syntax needs defeat
/// `looks_like_delimited_identifier`'s word-shaped-segment check (none of
/// those are alphanumeric), so it falls through to entropy scoring. The
/// brackets — on a string built only from the same narrow class-name
/// charset — are the signal: a real secret essentially never contains a
/// literal `[`/`]` pair, since none of the standard token encodings
/// (base64, hex, base62) use square brackets.
fn looks_like_tailwind_arbitrary_value(s: &str) -> bool {
    if !s.contains('[') || !s.contains(']') {
        return false;
    }
    const CLASS_CHARSET: &[u8] = b"[]-_:./%#(),&*!='\"+";
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || CLASS_CHARSET.contains(&b))
}

/// URLs, filesystem paths and Subresource-Integrity/lockfile hash prefixes:
/// all can be high-entropy but are not secrets.
fn looks_like_url_path_or_integrity_hash(s: &str) -> bool {
    const INTEGRITY_PREFIXES: &[&str] = &["sha1-", "sha256-", "sha384-", "sha512-"];
    s.contains("://")
        || s.starts_with("data:")
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('@')
        || (s.contains('/') && s.contains('.'))
        // Two or more path separators is a strong path/route signal on its
        // own — `refs/heads/main`, `api/auth/oauth/github/callback` — even
        // without a literal `.` anywhere in the string.
        || s.matches('/').count() >= 2
        || s.starts_with("urn:")
        || INTEGRITY_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// SQL fragments and ORM method-call chains — e.g.
/// `LOWER(I18n.transliterate(name)) LIKE ...` — are code, not secrets.
/// Matching is case-insensitive on common SQL keywords and tolerates
/// parenthesised method-call syntax (`fn(...)`).
fn looks_like_sql_or_query_fragment(s: &str) -> bool {
    let upper = s.to_uppercase();
    const SQL_KEYWORDS: &[&str] = &[
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WHERE ", " LIKE ",
        "LOWER(", "UPPER(", "COALESCE(", "CONCAT(", "TRIM(",
        "ORDER BY", "GROUP BY", "JOIN ", "FROM ",
    ];
    if SQL_KEYWORDS.iter().any(|kw| upper.contains(kw)) {
        return true;
    }
    // Method-call chains: `I18n.transliterate(...)`, `ActiveRecord::Base.connection`
    // — at least one `.word(` or `::word` pattern with balanced parens.
    let has_method_call = s.contains(".(")
        || (s.contains('.') && s.contains('(') && s.contains(')'));
    let has_namespace = s.contains("::");
    has_method_call && has_namespace
}

/// A regex pattern — `(?im-u)^\s*excludesfile\s*=\s*"?\s*(\S+?)\s*"?\s*$` —
/// rather than a secret. Character-class escapes (`\s`, `\d`, `\w`, ...)
/// combined with anchors/quantifiers/groups are not a shape any real token
/// encoding (base64, hex, base62) produces, but they read as high-entropy
/// noise to a charset-frequency count.
fn looks_like_regex_pattern(s: &str) -> bool {
    const CLASS_ESCAPES: &[&str] = &["\\s", "\\S", "\\d", "\\D", "\\w", "\\W", "\\b", "\\B"];
    const REGEX_SYNTAX: &[char] = &['^', '$', '(', ')', '?', '*', '+', '|'];
    CLASS_ESCAPES.iter().any(|e| s.contains(e)) && s.chars().any(|c| REGEX_SYNTAX.contains(&c))
}

/// HTTP header values and MIME type strings — `application/json`,
/// `text/html; charset=utf-8`, `multipart/form-data; boundary=...` — are
/// not secrets.
fn looks_like_http_or_mime_value(s: &str) -> bool {
    let lower = s.to_lowercase();
    const MIME_PREFIXES: &[&str] = &[
        "application/", "text/", "image/", "audio/", "video/",
        "multipart/", "font/", "model/", "message/",
    ];
    if MIME_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    // Common HTTP header names used as string values in source code.
    const HEADER_NAMES: &[&str] = &[
        "content-type", "content-disposition", "authorization",
        "cache-control", "accept-encoding", "x-requested-with",
        "access-control-allow",
    ];
    HEADER_NAMES.iter().any(|h| lower.contains(h))
}

/// A Rust `format!`-style interpolation template — `{candidate}`,
/// `{public_url}/api/...`, `{}` — is source code building a string, not the
/// secret value that ends up in it.
fn looks_like_format_template(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(rel_close) = s[i + 1..].find('}')
        {
            let inner = &s[i + 1..i + 1 + rel_close];
            let is_placeholder = inner.chars().all(|c| {
                c.is_alphanumeric()
                    || matches!(c, '_' | ':' | '.' | '?' | '#' | '<' | '>' | '^' | '+' | '-')
            });
            if is_placeholder {
                return true;
            }
            i += 1 + rel_close + 1;
            continue;
        }
        i += 1;
    }
    false
}

/// Real secrets/tokens are essentially always alphanumeric-plus-symbols
/// (base64, hex-with-mixed-context, or `prefix_base62...`); plain English
/// words and identifiers (camelCase, snake_case prose, kebab-case rule ids,
/// `namespace:name` pairs, dotted config keys) contain only letters plus
/// `_-:.,` structural punctuation. Requiring a digit or a symbol outside
/// that structural set filters most of that prose out while keeping actual
/// token shapes (base64 uses `+/=`, hex/base62 tokens carry digits, etc).
///
/// `=` is in the structural set even though base64 padding uses it too: a
/// real token has at most one or two trailing `=` and, being random, will
/// still carry a digit almost certainly, so `has_digit` alone still catches
/// it. What `=` filters out is `key=value`/build-directive syntax —
/// `cargo:rustc-link-arg-bin=rg=/MANIFEST:EMBED` — which repeats `=` as
/// plain code punctuation and has no digit to fall back on.
fn has_secret_like_charset(s: &str) -> bool {
    const STRUCTURAL: &[u8] = b"_-:.,/@()=";
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = s
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && !STRUCTURAL.contains(&b));
    has_digit || has_symbol
}

/// One `-`/`_`/`:`/`.`/`,`/`[`/`]`-separated piece of a longer string,
/// judged as "a word someone typed" rather than "a run of random bytes":
/// alphanumeric, short, and — when it carries digits — not also mixing
/// letter case. `missing`, `a11y`, `20250929` and `CamelCase` all pass;
/// `aG3n7Zq9Lm2XpW5` (mixed case *and* digits) and any run longer than a
/// plausible word do not.
fn is_word_like_segment(s: &str) -> bool {
    const MAX_WORD_LEN: usize = 15;
    if s.len() > MAX_WORD_LEN || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    !(has_digit && has_upper && has_lower)
}

/// A structured identifier — a rule id (`a11y:missing-lang-attribute`), a
/// model name (`claude-sonnet-4-5-20250929`), a dotted accessor path
/// (`.choices[0].message.content`), a glob pattern
/// (`docker-compose.*.yml`) — rather than a secret.
///
/// [`has_secret_like_charset`] alone lets all three through, because each
/// contains a digit, and that is the only signal it asks for. What
/// actually separates them from a token is *segmentation*: an identifier
/// is several short words joined by structural punctuation, while a
/// random token is one unbroken run (or, for a prefixed key like
/// `sk-proj-<random>`, a couple of short words followed by a long run
/// that is not a word). So: two or more segments, every one of them
/// word-like. `*` is a delimiter, not a word character: a real token
/// never contains a literal wildcard, so treating it as a separator
/// (rather than requiring it be part of some word-like segment) still
/// only ever recognizes glob syntax, never loosens the token check.
fn looks_like_delimited_identifier(s: &str) -> bool {
    const DELIMITERS: &[char] = &['-', '_', ':', '.', ',', '[', ']', '/', '@', '*'];
    let segments: Vec<&str> = s
        .split(DELIMITERS)
        .filter(|part| !part.is_empty())
        .collect();
    segments.len() >= 2 && segments.iter().all(|part| is_word_like_segment(part))
}

/// Real credentials (API keys, JWTs, OAuth tokens) essentially always carry
/// a recognizable prefix or header, because every issuer stamps its own
/// format on them: `sk-`/`sk_` (OpenAI/Stripe secret keys), `pk_live_`/
/// `pk_test_` (Stripe publishable keys), `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/
/// `github_pat_` (GitHub tokens), `AKIA`/`ASIA` (AWS access key ids),
/// `xox[abps]-` (Slack tokens), `AIza` (Google API keys), `eyJ` (the base64
/// of a JWT's `{"` header), and `-----BEGIN` (PEM-encoded keys/certs). A
/// long opaque blob with none of these is far more likely to be serialized
/// data (a base64-encoded asset, preset, or payload) than a secret.
const KNOWN_SECRET_PREFIXES: &[&str] = &[
    "sk-", "sk_", "pk_live_", "pk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghu_", "ghs_",
    "ghr_", "github_pat_", "AKIA", "ASIA", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxr-", "AIza",
    "eyJ", "-----BEGIN",
];

fn has_known_secret_prefix(s: &str) -> bool {
    KNOWN_SECRET_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// JSON object key substrings (matched after stripping quotes/punctuation
/// and lowercasing) that mark the value they label as credential-shaped —
/// `apiKey`, `access_token`, `Authorization`, `client-secret`, ... — as
/// opposed to a generic data-carrier key like `value`/`data`/`payload`.
const SENSITIVE_KEY_HINTS: &[&str] = &[
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "authorization",
    "accesskey",
    "privatekey",
    "clientsecret",
    "bearer",
];

/// Normalizes a JSON/object key to bare lowercase letters+digits (dropping
/// `_`/`-`/quotes/whitespace) so `api_key`, `apiKey` and `"API-KEY"` all
/// compare equal, then checks it against [`SENSITIVE_KEY_HINTS`].
fn key_looks_sensitive(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_KEY_HINTS.iter().any(|h| normalized.contains(h))
}

/// A value string this long with no recognizable secret prefix
/// ([`has_known_secret_prefix`]) reads as serialized data (base64 assets,
/// presets, encoded payloads), not a credential — real API keys, tokens and
/// even most JWTs stay well under this. Values under a sensitive-looking
/// JSON key ([`key_looks_sensitive`]) are exempt: a legitimately long secret
/// (e.g. a PEM-less RSA blob under `"privateKey"`) should still be caught.
const MAX_LENGTH_WITHOUT_KNOWN_PREFIX: usize = 200;

fn is_json_pair(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "pair")
}

/// Walks the tree collecting, for every JSON `pair` node, a mapping from its
/// value node's start position to the pair's own (unquoted, lowercased) key
/// text. `AstNode` has no parent pointer, so a value's enclosing key can
/// only be recovered by walking down from the pair rather than up from the
/// value — this builds that lookup once per file instead of re-walking for
/// every string literal.
fn collect_json_pair_keys(node: &AstNode, out: &mut HashMap<(u32, u32), String>) {
    if is_json_pair(node)
        && let [key, value, ..] = node.children()
        && *key.kind() == NodeKind::StringLiteral
    {
        let span = value.span();
        out.insert(
            (span.start_line, span.start_col),
            strip_quotes(key.text()).to_lowercase(),
        );
    }
    for child in node.children() {
        collect_json_pair_keys(child, out);
    }
}

/// One candidate high-entropy literal, held back from becoming a `Finding`
/// until the whole file has been scanned so [`suppress_bulk_data_clusters`]
/// can see the full picture.
struct Candidate {
    message: String,
    span: vord_ast::Span,
    value_len: usize,
    is_sensitive: bool,
}

/// Many near-identical-length high-entropy strings in one file is the
/// signature of a serialized data array (presets, samples, embedded
/// assets) rather than of scattered secrets — a real credential leak does
/// not usually arrive in a block of dozens of same-shaped values. When a
/// file has at least [`CLUSTER_MIN_COUNT`] candidates whose lengths fall
/// within [`CLUSTER_LENGTH_TOLERANCE`] of the group's median, and none of
/// them carry a sensitive key name or a known secret prefix, the whole
/// cluster is suppressed rather than reported one-by-one.
const CLUSTER_MIN_COUNT: usize = 6;
const CLUSTER_LENGTH_TOLERANCE: f64 = 0.15;

fn suppress_bulk_data_clusters(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut lengths: Vec<usize> = candidates.iter().map(|c| c.value_len).collect();
    lengths.sort_unstable();
    let median = match lengths.len() {
        0 => return candidates,
        n => lengths[n / 2] as f64,
    };
    let tolerance = (median * CLUSTER_LENGTH_TOLERANCE).max(1.0);
    let in_band: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| ((c.value_len as f64) - median).abs() <= tolerance)
        .collect();
    let is_bulk_cluster =
        in_band.len() >= CLUSTER_MIN_COUNT && in_band.iter().all(|c| !c.is_sensitive);
    if !is_bulk_cluster {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|c| ((c.value_len as f64) - median).abs() > tolerance || c.is_sensitive)
        .collect()
}

/// Flags string literals whose Shannon entropy is high enough to look like
/// a random token/key, regardless of provider — the catch-all for
/// private/self-hosted services and formats without a dedicated pattern.
pub struct HighEntropyStringRule {
    id: RuleId,
    /// Minimum entropy, in bits per character, to flag.
    threshold: f64,
    /// Minimum literal length (post quote-stripping) to consider — short
    /// strings don't carry enough signal to score reliably.
    min_length: usize,
    /// JSON/object key names (lowercased) whose values are never flagged,
    /// however high their entropy — the project's own declaration that a
    /// key like `"value"` or `"preset"` holds serialized data, not a
    /// credential. Configured via `vord.toml`'s `[secrets] ignore_keys`.
    ignore_keys: Vec<String>,
}

impl HighEntropyStringRule {
    pub fn new() -> Self {
        Self::with_config(3.5, 20, Vec::new())
    }

    /// Builds the rule with a custom threshold/minimum length, e.g. for a
    /// stricter or looser profile.
    pub fn with_threshold(threshold: f64, min_length: usize) -> Self {
        Self::with_config(threshold, min_length, Vec::new())
    }

    /// Builds the rule with the default threshold/minimum length plus a
    /// project-declared list of JSON/object key names to never flag —
    /// `vord.toml`'s `[secrets] ignore_keys`.
    pub fn with_ignore_keys(ignore_keys: Vec<String>) -> Self {
        Self::with_config(3.5, 20, ignore_keys)
    }

    fn with_config(threshold: f64, min_length: usize, ignore_keys: Vec<String>) -> Self {
        Self {
            id: RuleId::new("secrets:high-entropy-string").expect("valid rule id"),
            threshold,
            min_length,
            ignore_keys: ignore_keys.into_iter().map(|k| k.to_lowercase()).collect(),
        }
    }
}

impl Default for HighEntropyStringRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HighEntropyStringRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "String literal has high Shannon entropy and looks like a random token/key rather than ordinary text. Catches unclassified and private/self-hosted service secrets that don't match a known provider format.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path().to_lowercase();
        if path.ends_with(".lock")
            || path.contains("-lock.")
            || path.ends_with(".yaml")
            || path.ends_with(".yml")
            || path.contains("/i18n/")
            || path.contains("/locales/")
            || path.contains("/lang/")
            || path.contains("/translations/")
            || path.ends_with(".po")
            || path.ends_with(".pot")
            || path.contains("rulesets/secrets")
            // Same rationale as the `rulesets/secrets` exclusion above:
            // owasp's own detection rules (jwt-none-algorithm,
            // session-id-in-url, open-redirect, api-key-in-query-string,
            // logging-sensitive-data, ...) are dense with long regex
            // pattern literals that read as high-entropy tokens without
            // being credentials.
            || path.contains("rulesets/owasp")
        {
            return Vec::new();
        }
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let mut json_pair_keys = HashMap::new();
        collect_json_pair_keys(ast, &mut json_pair_keys);

        let mut candidates = Vec::new();

        for literal in ast
            .descendants()
            .filter(|n| *n.kind() == NodeKind::StringLiteral)
        {
            if vord_rules_engine::in_ranges(&test_ranges, literal.span().start_line) {
                continue;
            }
            let value = unescape_common(strip_quotes(literal.text()));
            let value = value.as_str();

            if value.len() < self.min_length || !value.is_ascii() || value.contains(char::is_whitespace) {
                continue;
            }
            if looks_like_hex_digest(value)
                || looks_like_uuid(value)
                || looks_like_url_path_or_integrity_hash(value)
                || looks_like_format_template(value)
                || looks_like_delimited_identifier(value)
                || looks_like_css_variable(value)
                || looks_like_known_charset_alphabet(value)
                || looks_like_tailwind_arbitrary_value(value)
                || looks_like_sql_or_query_fragment(value)
                || looks_like_http_or_mime_value(value)
                || looks_like_regex_pattern(value)
            {
                continue;
            }
            if !has_secret_like_charset(value) {
                continue;
            }

            let span = literal.span();
            let key = json_pair_keys.get(&(span.start_line, span.start_col));
            if let Some(key) = key
                && self.ignore_keys.iter().any(|k| k == key)
            {
                continue;
            }
            let is_sensitive = key.is_some_and(|k| key_looks_sensitive(k));

            if !is_sensitive
                && value.len() > MAX_LENGTH_WITHOUT_KNOWN_PREFIX
                && !has_known_secret_prefix(value)
            {
                continue;
            }

            let entropy = shannon_entropy(value);
            if entropy >= self.threshold {
                candidates.push(Candidate {
                    message: format!(
                        "string literal has high entropy ({entropy:.2} bits/char over {} chars) and looks like a random secret/token",
                        value.chars().count()
                    ),
                    span,
                    value_len: value.len(),
                    is_sensitive: is_sensitive || has_known_secret_prefix(value),
                });
            }
        }

        suppress_bulk_data_clusters(candidates)
            .into_iter()
            .map(|c| Finding::new(c.message, c.span))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        HighEntropyStringRule::new().check(&file, &ast)
    }

    fn check_json_with(rule: &HighEntropyStringRule, code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.json", code, LanguageIdentifier::json()).unwrap();
        let ast = vord_parser_json::JsonParser::new().parse(&file).unwrap();
        rule.check(&file, &ast)
    }

    fn check_json(code: &str) -> Vec<Finding> {
        check_json_with(&HighEntropyStringRule::new(), code)
    }

    fn base64_blob(len: usize) -> String {
        // No `/`: two or more slashes reads as a path
        // (`looks_like_url_path_or_integrity_hash`), which is exactly the
        // kind of non-secret shape these tests are not exercising.
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+";
        // A deterministic pseudo-random walk over the base64 alphabet —
        // high entropy without pulling in a real RNG dependency just for a
        // test fixture.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                ALPHABET[(state % ALPHABET.len() as u64) as usize] as char
            })
            .collect()
    }

    #[test]
    fn entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn flags_random_looking_token() {
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!("const apiToken = \"{token}\";\n");
        let findings = check_ts(&code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_structured_identifiers_that_merely_contain_digits() {
        // The regression this guards: `has_secret_like_charset` accepts any
        // string containing a digit, so a rule id, a model name and a
        // dotted accessor path all cleared it and then scored above the
        // entropy threshold on character variety alone. All three are
        // source-code identifiers sitting in plain sight, not credentials.
        for identifier in [
            "a11y:missing-lang-attribute",
            "claude-sonnet-4-5-20250929",
            ".choices[0].message.content",
            "secrets:high-entropy-string",
            "text-embedding-3-small",
        ] {
            let code = format!("const x = \"{identifier}\";\n");
            assert!(
                check_ts(&code).is_empty(),
                "flagged identifier {identifier} as a secret"
            );
        }
    }

    #[test]
    fn still_flags_a_prefixed_token_whose_random_half_is_not_word_like() {
        // The guard on the exemption above: a `prefix-prefix-<random>` key
        // is segmented too, but its payload segment is neither short nor
        // word-shaped, so it must still be caught.
        let token = ["sk-proj-aG3n7", "Zq9Lm2Xp", "W5vBt8FhKc1RdSy"].concat();
        let code = format!("const k = \"{token}\";\n");
        assert_eq!(check_ts(&code).len(), 1);
    }

    #[test]
    fn ignores_short_strings() {
        assert!(check_ts("const x = \"aB3!\";\n").is_empty());
    }

    #[test]
    fn ignores_plain_english_sentence() {
        let code = "const msg = \"could not connect to the database, please retry\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_common_identifier_style_text() {
        let code =
            "const description = \"aVeryDescriptiveHumanReadableConfigurationOptionName\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_git_sha1_and_sha256() {
        let code = "const commit = \"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\";\n\
                    const digest = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_uuid() {
        let code = "const requestId = \"550e8400-e29b-41d4-a716-446655440000\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_urls_and_paths() {
        let code = "const url = \"https://example.com/some/very/long/descriptive/path\";\n\
                    const p = \"/usr/local/share/some-long-application-name/config\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_subresource_integrity_hash() {
        let code = "const sri = \"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_snake_case_identifier_style_text() {
        assert!(check_ts("const m = \"vord_process_uptime_seconds\";\n").is_empty());
    }

    #[test]
    fn ignores_namespaced_kebab_case_rule_ids() {
        assert!(check_ts("const rule = \"owasp:hardcoded-secret\";\n").is_empty());
    }

    #[test]
    fn ignores_dotted_config_keys_and_comma_joined_lists() {
        assert!(check_ts("const key = \"analysis.exclusions.default\";\n").is_empty());
        assert!(check_ts("const list = \"read:user,user:email,repo:status\";\n").is_empty());
    }

    #[test]
    fn ignores_format_string_placeholders() {
        assert!(
            check_ts("const url = \"{public_url}/api/auth/oauth/github/callback\";\n").is_empty()
        );
        assert!(check_ts("const metric = \"vord_http_requests_total{{method=\\\"{}\\\",route=\\\"{}\\\"}}\";\n").is_empty());
    }

    #[test]
    fn ignores_comma_joined_header_row_with_trailing_newline_escape() {
        let code = "const h = \"rule_id,severity,file_path,start_line,message\\n\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_urn_identifiers() {
        assert!(
            check_ts("const s = \"urn:ietf:params:scim:api:messages:2.0:ListResponse\";\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_extensionless_multi_segment_paths() {
        assert!(check_ts("const p = \"refs/remotes/origin/HEAD\";\n").is_empty());
        assert!(check_ts("const p2 = \"api/auth/oauth/github/callback\";\n").is_empty());
    }

    #[test]
    fn respects_custom_threshold() {
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!("const apiToken = \"{token}\";\n");
        let file = SourceFile::new("t.ts", &*code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let strict_rule = HighEntropyStringRule::with_threshold(5.9, 20);
        assert!(strict_rule.check(&file, &ast).is_empty());
    }

    #[test]
    fn ignores_lockfiles_and_yaml_files() {
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!("const apiToken = \"{token}\";\n");

        let file =
            SourceFile::new("pnpm-lock.yaml", &*code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        assert!(HighEntropyStringRule::new().check(&file, &ast).is_empty());

        let file = SourceFile::new("Cargo.lock", &*code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        assert!(HighEntropyStringRule::new().check(&file, &ast).is_empty());

        let file = SourceFile::new("some.yaml", &*code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        assert!(HighEntropyStringRule::new().check(&file, &ast).is_empty());

        let file = SourceFile::new("other.yml", &*code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        assert!(HighEntropyStringRule::new().check(&file, &ast).is_empty());
    }

    #[test]
    fn ignores_css_variables() {
        assert!(check_ts("const c = \"var(--color-expenses)\";\n").is_empty());
        assert!(check_ts("const c = \"var(--color-signups)\";\n").is_empty());
    }

    #[test]
    fn ignores_sql_fragments_with_like_and_lower() {
        // I18n.transliterate pattern from Rails codebases
        let code = "const q = \"LOWER(I18n.transliterate(name)) LIKE LOWER(I18n.transliterate(search))\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_sql_select_and_where_clauses() {
        let code = "const q = \"SELECT name, email FROM users WHERE active = true\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_mime_type_strings() {
        assert!(check_ts("const ct = \"application/json; charset=utf-8\";\n").is_empty());
        assert!(check_ts("const ct = \"multipart/form-data; boundary=something\";\n").is_empty());
        assert!(check_ts("const ct = \"text/html; charset=iso-8859-1\";\n").is_empty());
    }

    #[test]
    fn ignores_http_header_name_values() {
        assert!(
            check_ts("const h = \"Content-Type: application/x-www-form-urlencoded\";\n").is_empty()
        );
    }

    #[test]
    fn ignores_tailwind_arbitrary_value_classes() {
        // All from real code: bulletproof-react's table.tsx and shadcn/ui's
        // sidebar.tsx / tooltip.tsx (vercel/ai-chatbot).
        for class in [
            "[&_tr:last-child]:border-0",
            "grid-cols-[repeat(auto-fill,minmax(120px,1fr))]",
            "group-data-[side=left]:cursor-e-resize",
            "aria-[current=page]:bg-accent",
            "group-data-[collapsible=icon]:w-[calc(var(--sidebar-width-icon)+(--spacing(4)))]",
        ] {
            let code = format!("const c = \"{class}\";\n");
            assert!(check_ts(&code).is_empty(), "flagged tailwind class {class}");
        }
    }

    #[test]
    fn ignores_key_value_build_directives() {
        // From ripgrep's build.rs: `=` repeated as plain code punctuation,
        // no digit anywhere, so only the (now-structural) `=` made it read
        // as high entropy before.
        assert!(
            check_ts("const s = \"cargo:rustc-link-arg-bin=rg=/MANIFEST:EMBED\";\n").is_empty()
        );
    }

    #[test]
    fn ignores_regex_patterns() {
        // From ripgrep's gitignore.rs.
        assert!(check_ts(
            r#"const re = "(?im-u)^\s*excludesfile\s*=\s*\"?\s*(\S+?)\s*\"?\s*$";
"#
        )
        .is_empty());
    }

    #[test]
    fn ignores_glob_patterns_with_wildcards() {
        assert!(check_ts("const g = \"docker-compose.*.yml\";\n").is_empty());
        assert!(check_ts("const g = \"*.terraform.lock.hcl\";\n").is_empty());
    }

    #[test]
    fn strip_quotes_drops_byte_and_raw_string_prefixes() {
        assert_eq!(strip_quotes(r#"b"abc""#), "abc");
        assert_eq!(strip_quotes(r#"r"abc""#), "abc");
        assert_eq!(strip_quotes(r#"br"abc""#), "abc");
        assert_eq!(strip_quotes(r#"rb"abc""#), "abc");
        assert_eq!(strip_quotes(r#""abc""#), "abc");
    }

    #[test]
    fn ignores_known_charset_alphabet_constants() {
        // Matches ripgrep's `const ALPHABET: &[u8] = b"ABC...+/";` shape
        // once `strip_quotes` drops the `b` prefix.
        let literal = "b\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"";
        assert!(looks_like_known_charset_alphabet(strip_quotes(literal)));
    }

    #[test]
    fn ignores_code_expressions_with_parentheses() {
        // Regression: `datetime.utcfromtimestamp(` and `datetime.utcnow()` are
        // well-known Python API method names containing parens — parens are code
        // syntax, not random-token characters. STRUCTURAL now includes `()`.
        assert!(check_ts("const s = \"datetime.utcfromtimestamp(\";\n").is_empty());
        assert!(check_ts("const s = \"datetime.utcnow()\";\n").is_empty());
        assert!(check_ts("const call = \"console.log(42)\";\n").is_empty());
    }

    #[test]
    fn ignores_long_base64_blob_under_a_generic_json_key() {
        // The regression this guards: a base64-encoded preset/asset blob
        // (800-960 chars in the real report) stored under a generic key
        // like "value" is serialized data, not a credential — it has no
        // recognizable secret prefix and is far longer than any real token.
        let blob = base64_blob(900);
        let code = format!("{{\"value\": \"{blob}\"}}");
        assert!(check_json(&code).is_empty());
    }

    #[test]
    fn still_flags_long_blob_under_a_sensitive_json_key() {
        // The guard on the exemption above: a value this long under a key
        // that actually looks like a credential name must still be caught,
        // e.g. a raw (non-PEM) RSA key stored under "privateKey".
        let blob = base64_blob(900);
        let code = format!("{{\"privateKey\": \"{blob}\"}}");
        assert_eq!(check_json(&code).len(), 1);
    }

    #[test]
    fn still_flags_long_blob_with_a_known_secret_prefix() {
        // A JWT can legitimately run past the generic length cutoff; the
        // `eyJ` header keeps it flagged even under a generic key name.
        let jwt = format!("eyJ{}", base64_blob(300));
        let code = format!("{{\"value\": \"{jwt}\"}}");
        assert_eq!(check_json(&code).len(), 1);
    }

    #[test]
    fn ignores_moderate_length_secret_under_a_configured_ignore_key() {
        let rule = HighEntropyStringRule::with_ignore_keys(vec!["value".to_string()]);
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!("{{\"value\": \"{token}\"}}");
        assert!(check_json_with(&rule, &code).is_empty());

        // A differently-cased key still matches (keys are normalized).
        let code2 = format!("{{\"VALUE\": \"{token}\"}}");
        assert!(check_json_with(&rule, &code2).is_empty());
    }

    #[test]
    fn ignore_keys_do_not_suppress_other_keys() {
        let rule = HighEntropyStringRule::with_ignore_keys(vec!["value".to_string()]);
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!("{{\"apiKey\": \"{token}\"}}");
        assert_eq!(check_json_with(&rule, &code).len(), 1);
    }

    #[test]
    fn suppresses_a_bulk_cluster_of_similar_length_high_entropy_strings() {
        // 43 near-identical-length base64 blobs in one array, all under the
        // same generic key, is the signature of serialized preset/asset
        // data — not 43 separate leaked secrets.
        let entries: Vec<String> = (0..12)
            .map(|i| format!("{{\"value\": \"{}\"}}", base64_blob(120 + i)))
            .collect();
        let code = format!("[{}]", entries.join(","));
        assert!(check_json(&code).is_empty());
    }

    #[test]
    fn does_not_suppress_a_lone_secret_alongside_unrelated_short_strings() {
        // A single real secret must not get caught in cluster suppression
        // just because other unrelated (short, non-candidate) strings share
        // the file.
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        let code = format!(
            "{{\"name\": \"my-app\", \"description\": \"just a normal app\", \"apiKey\": \"{token}\"}}"
        );
        assert_eq!(check_json(&code).len(), 1);
    }
}
