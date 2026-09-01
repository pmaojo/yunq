//! Application wiring for the vord CLI: composes the default parsers,
//! rulesets and profile into an `AnalyzerService` and exposes the scan
//! use-case plus the output DTOs (serialization lives here, at the edge —
//! never on domain types).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vord_infra_fs::FileAnalysisCache;
use vord_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use vord_parser_bash::BashParser;
use vord_parser_c::CParser;
use vord_parser_cpp::CppParser;
use vord_parser_csharp::CSharpParser;
use vord_parser_css::CssParser;
use vord_parser_dockerfile::DockerfileParser;
use vord_parser_elixir::ElixirParser;
use vord_parser_go::GoParser;
use vord_parser_groovy::GroovyParser;
use vord_parser_hcl::HclParser;
use vord_parser_html::HtmlParser;
use vord_parser_java::JavaParser;
use vord_parser_json::JsonParser;
use vord_parser_kotlin::KotlinParser;
use vord_parser_lua::LuaParser;
use vord_parser_php::PhpParser;
use vord_parser_python::PythonParser;
use vord_parser_ruby::RubyParser;
use vord_parser_rust::RustParser;
use vord_parser_scala::ScalaParser;
use vord_parser_swift::SwiftParser;
use vord_parser_typescript::TypeScriptParser;
use vord_parser_xml::XmlParser;
use vord_parser_yaml::YamlParser;
use vord_rules_engine::{
    AnalysisReport, AnalyzerService, ComparisonOperator, Condition, HotspotStorage, IssueStorage,
    MetricKey, MetricsTracker, QualityGate, Rule, Severity,
};

pub mod agent;
pub mod hook;
pub mod output;
pub mod swarm;
pub mod triage;

/// Every parser the default service registers. Its own flat data literal
/// (complexity 1) so `default_service` doesn't carry the whole fluent
/// registration chain's line count. Public so callers that need a one-off
/// parse outside `AnalyzerService`'s own pipeline (e.g. `bin/cli::flow`'s
/// flow-coverage re-parse) can build the same registry without duplicating
/// this list.
pub fn all_default_parsers() -> Vec<Box<dyn vord_rules_engine::AstParser>> {
    vec![
        Box::new(TypeScriptParser::new()),
        Box::new(RustParser::new()),
        Box::new(PythonParser::new()),
        Box::new(GoParser::new()),
        Box::new(JavaParser::new()),
        Box::new(CParser::new()),
        Box::new(CppParser::new()),
        Box::new(PhpParser::new()),
        Box::new(DockerfileParser::new()),
        Box::new(CSharpParser::new()),
        Box::new(RubyParser::new()),
        Box::new(KotlinParser::new()),
        Box::new(SwiftParser::new()),
        Box::new(ScalaParser::new()),
        Box::new(HtmlParser::new()),
        Box::new(CssParser::new()),
        Box::new(XmlParser::new()),
        Box::new(JsonParser::new()),
        Box::new(YamlParser::new()),
        Box::new(HclParser::new()),
        Box::new(BashParser::new()),
        Box::new(GroovyParser::new()),
        Box::new(LuaParser::new()),
        Box::new(ElixirParser::new()),
    ]
}

/// Builds the default analyzer: both parsers, every shipped rule, and the
/// built-in "vord way" profile (`vord_profiles::default_profile`) — a curated
/// per-language activation baseline, not merely "every registered rule at
/// its default severity". This is what a project with no explicit profile
/// assignment gets (see issue #22): there is currently no per-project
/// profile assignment mechanism in this codebase (mirroring the note in
/// `bin/server/src/ops.rs` that per-project *gate* assignment exists but
/// per-project *profile* assignment is still "Fase 3 territory"), so the
/// vord way profile is the sole default every scan uses today.
///
/// `vord_rules_vite_react::all_rules()` is registered unconditionally along
/// with every other ruleset, same as the rest of this chain — it's inert
/// unless the active profile activates a `vite-react:*` id
/// (`AnalyzerService::check` filters by `profile.is_active`), and "vord way"
/// never does, so this is safe with no `--profile` selected at all.
pub fn default_service<S, M>(storage: S, metrics: M) -> AnalyzerService<S, M>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    let rules: Vec<Box<dyn Rule>> = vord_rules_owasp::all_rules()
        .into_iter()
        .chain(vord_rules_smells::all_rules())
        .chain(vord_rules_iac::all_rules())
        .chain(vord_rules_a11y::all_rules())
        .chain(vord_rules_react::all_rules())
        .chain(vord_rules_secrets::all_rules())
        .chain(vord_rules_rust::all_rules())
        .chain(vord_rules_reactive::all_rules())
        .chain(vord_rules_python::all_rules())
        .chain(vord_rules_typescript::all_rules())
        .chain(vord_rules_php::all_rules())
        .chain(vord_rules_wordpress::all_rules())
        .chain(vord_rules_go::all_rules())
        .chain(vord_rules_ai_agent::all_rules())
        .chain(vord_rules_architecture::all_rules())
        .chain(vord_rules_ddd::all_rules())
        .chain(vord_rules_mutation::all_rules())
        .chain(vord_rules_vite_react::all_rules())
        .collect();
    let cross_rules: Vec<Box<dyn vord_rules_engine::CrossFileRule>> =
        vord_rules_owasp::all_cross_rules()
            .into_iter()
            .chain(vord_rules_architecture::all_cross_rules())
            .chain(vord_rules_smells::all_cross_rules())
            .chain(vord_rules_ddd::all_cross_rules())
            .chain(vord_rules_rust::all_cross_rules())
            .collect();
    let profile = vord_rules_engine::default_profile();

    let mut service = AnalyzerService::new(profile, storage, metrics);
    for parser in all_default_parsers() {
        service = service.register_parser(parser);
    }
    for rule in rules {
        service = service.register_rule(rule);
    }
    for rule in cross_rules {
        service = service.register_cross_rule(rule);
    }
    service
}

/// The built-in quality gate: no blocker or critical issues, and every file
/// must parse. Mirrors the Clean-as-You-Code default until per-project gates
/// arrive with the server-side quality model.
pub fn default_quality_gate() -> QualityGate {
    let metric = |raw: &str| MetricKey::new(raw).expect("valid metric key");
    QualityGate::new("vord-default")
        .with_condition(Condition::new(
            metric("blocker_issues"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
        .with_condition(Condition::new(
            metric("critical_issues"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
        .with_condition(Condition::new(
            metric("parse_failures"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
        // NoValue (ignored) unless a coverage report was ingested.
        .with_condition(Condition::new(
            metric("coverage"),
            ComparisonOperator::LessThan,
            80.0,
        ))
        // NoValue (ignored) unless a mutation-testing report was ingested
        // (`--mutation-report`). 60 mirrors Stryker's own conventional "low" threshold.
        .with_condition(Condition::new(
            metric("mutation_score"),
            ComparisonOperator::LessThan,
            60.0,
        ))
        // NoValue (ignored) unless a coverage report was ingested. Counts
        // only functions already past crap4clj's "complex *and* untested"
        // band (CRAP score > 30) — the same zero-tolerance treatment
        // blocker/critical issues get, since the threshold has already done
        // the filtering a raw coverage percentage can't: it says *where*
        // the untested code is, not just how much of it there is.
        .with_condition(Condition::new(
            metric("crap_high_risk_functions"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
}

/// The `vite-react-frontend-starter` profile's quality gate: the same
/// blocker/critical/parse-failure conditions as [`default_quality_gate`],
/// minus its `coverage`/`mutation_score` conditions — Vord doesn't measure
/// JS test coverage or run mutants itself, that's `pnpm test`'s (and, for
/// mutation, Stryker's) job, wired separately into the pre-push/CI composite
/// command documented in `docs/starters/vite-react-frontend-starter.md`
/// rather than into this gate. Coupled to the `--profile` selection by
/// `quality_gate_for_profile`.
pub fn vite_react_gate() -> QualityGate {
    let metric = |raw: &str| MetricKey::new(raw).expect("valid metric key");
    QualityGate::new("vord-vite-react-frontend-starter")
        .with_condition(Condition::new(
            metric("blocker_issues"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
        .with_condition(Condition::new(
            metric("critical_issues"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
        .with_condition(Condition::new(
            metric("parse_failures"),
            ComparisonOperator::GreaterThan,
            0.0,
        ))
}

/// The quality gate `--profile <name>` selects: [`vite_react_gate`] for the
/// `vite-react-frontend-starter` profile, [`default_quality_gate`] for
/// every other name (including no `--profile` at all, so the default path
/// is unchanged).
pub fn quality_gate_for_profile(profile_name: Option<&str>) -> QualityGate {
    match profile_name {
        Some(vord_rules_engine::VITE_REACT_FRONTEND_STARTER_NAME) => vite_react_gate(),
        _ => default_quality_gate(),
    }
}

/// Resolves an issue's `(file, line)` to that source line's content hash for
/// the New Code tracking cascade (`vord_rules_engine::new_code::line_hash`),
/// reading each file from disk at most once per scan. `file` is the path as
/// recorded on `Issue` — relative to the scan root, exactly as
/// `collect_sources` produces it.
pub struct FileLineHashes {
    root: PathBuf,
    cache: RefCell<HashMap<String, Vec<u64>>>,
}

impl FileLineHashes {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// `None` when the file can't be read (deleted/moved/binary) or `line`
    /// (1-based) is past the end of the cached content — the tracking
    /// cascade then falls back to the message fingerprint for that issue.
    pub fn hash(&self, file: &str, line: u32) -> Option<u64> {
        let mut cache = self.cache.borrow_mut();
        if !cache.contains_key(file) {
            let hashes = std::fs::read_to_string(self.root.join(file))
                .map(|text| text.lines().map(vord_rules_engine::line_hash).collect())
                .unwrap_or_default();
            cache.insert(file.to_string(), hashes);
        }
        let hashes = cache.get(file)?;
        let index = (line as usize).checked_sub(1)?;
        hashes.get(index).copied()
    }
}

/// Scans a directory (or single file) with the default analyzer, without a
/// cache — fully deterministic, used by tests and one-off scans.
pub async fn scan(path: &Path) -> anyhow::Result<AnalysisReport> {
    scan_with_cache(path, None).await
}

/// Scans with an optional incremental cache; the caller decides persistence.
/// Does not apply any `vord.toml` exclusions — see [`scan_with_exclusions`]
/// for callers that have already loaded the project config.
pub async fn scan_with_cache(
    path: &Path,
    cache: Option<Arc<FileAnalysisCache>>,
) -> anyhow::Result<AnalysisReport> {
    scan_with_exclusions(path, cache, &[]).await
}

/// Scans with an optional incremental cache and `vord.toml`'s
/// `[analysis] exclusions` globs (matched against each file's path relative
/// to `path`).
pub async fn scan_with_exclusions(
    path: &Path,
    cache: Option<Arc<FileAnalysisCache>>,
    exclusions: &[String],
) -> anyhow::Result<AnalysisReport> {
    scan_with_project_config(
        path,
        cache,
        &[],
        &[],
        exclusions,
        &Default::default(),
        &Default::default(),
    )
    .await
}

/// Scans with an optional incremental cache, `vord.toml`'s
/// `[analysis] sources` (directories to scan — the whole tree when empty),
/// `[analysis] inclusions` (a file must match at least one to be kept, when
/// non-empty), and `[analysis] exclusions` globs (matched against each
/// file's path relative to `path`). Always the "vord way" default profile
/// with no `[vite_react.exceptions]` applied — see [`scan_with_profile`] for
/// a caller that has resolved a `--profile` selection.
pub async fn scan_with_project_config(
    path: &Path,
    cache: Option<Arc<FileAnalysisCache>>,
    source_dirs: &[String],
    inclusions: &[String],
    exclusions: &[String],
    duplication: &vord_infra_fs::DuplicationSettings,
    architecture: &vord_infra_fs::ArchitectureSettings,
) -> anyhow::Result<AnalysisReport> {
    scan_with_profile(
        path,
        cache,
        source_dirs,
        inclusions,
        exclusions,
        &ProjectSettings {
            duplication,
            architecture,
            vite_react: &Default::default(),
            secrets: &Default::default(),
            rules_custom: &[],
        },
        None,
    )
    .await
}

/// The `vord.toml` setting tables [`scan_with_profile`] needs beyond scope
/// and cache — bundled purely to keep that function's argument count
/// reasonable; each field is exactly the struct its own `vord.toml` section
/// deserializes to.
pub struct ProjectSettings<'a> {
    pub duplication: &'a vord_infra_fs::DuplicationSettings,
    pub architecture: &'a vord_infra_fs::ArchitectureSettings,
    pub vite_react: &'a vord_infra_fs::ViteReactSettings,
    /// `[secrets] ignore_keys` — JSON/object key names whose values
    /// `secrets:high-entropy-string` never flags, bridged (via
    /// `HighEntropyStringRule::with_ignore_keys`) into the rule the same
    /// way `vite_react` above bridges into `rulesets/vite-react`'s rules.
    pub secrets: &'a vord_infra_fs::SecretsSettings,
    /// `[[rules.custom]]` — project-declared regex rules. Each entry is
    /// registered as an ordinary `vord_rules_smells::CustomRule` *and*
    /// explicitly activated on top of whatever profile is otherwise in
    /// effect: a user-chosen rule id can never be pre-listed in the
    /// built-in "vord way" profile (`core/profiles::default_profile` is a
    /// hand-maintained literal list of vord's own shipped rule ids), so
    /// without this a custom rule would register successfully and then be
    /// silently filtered out by `QualityProfile::is_active` on every scan —
    /// exactly the "config accepted, nothing happens" trap this closes.
    pub rules_custom: &'a [vord_infra_fs::CustomRuleConfig],
}

/// Same as [`scan_with_project_config`], plus `vord.toml`'s
/// `[vite_react.exceptions]` (bridged via [`vite_react_config`] into each
/// `rulesets/vite-react` rule's own `with_exceptions` constructor) and an
/// optional resolved `QualityProfile` — `None` keeps today's "vord way"
/// default exactly as [`scan_with_project_config`] always has, so this is
/// the one place `--profile` actually changes what a scan measures.
pub async fn scan_with_profile(
    path: &Path,
    cache: Option<Arc<FileAnalysisCache>>,
    source_dirs: &[String],
    inclusions: &[String],
    exclusions: &[String],
    settings: &ProjectSettings<'_>,
    profile: Option<vord_rules_engine::QualityProfile>,
) -> anyhow::Result<AnalysisReport> {
    let duplication = settings.duplication;
    let architecture = settings.architecture;
    let vite_react = settings.vite_react;
    let sources = vord_infra_fs::collect_sources_scoped(path, source_dirs, inclusions, exclusions)?;
    let mut service = default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new())
        .with_duplication_config(duplication_config(duplication));
    if let Some(profile) = profile {
        service = service.with_profile(profile);
    }
    for (rule_id, globs) in vite_react_config(vite_react) {
        if let Some(rule) = vite_react_rule_with_exceptions(&rule_id, globs) {
            service = service.replace_rule(rule);
        }
    }
    if !settings.secrets.ignore_keys.is_empty() {
        service = service.replace_rule(Box::new(
            vord_rules_secrets::HighEntropyStringRule::with_ignore_keys(
                settings.secrets.ignore_keys.clone(),
            ),
        ));
    }
    if !settings.rules_custom.is_empty() {
        let mut profile = service.profile().clone();
        for config in settings.rules_custom {
            let severity = Severity::parse(&config.severity).ok_or_else(|| {
                anyhow::anyhow!(
                    "[[rules.custom]] {:?} has an unknown severity {:?} (expected info|minor|major|critical|blocker)",
                    config.id,
                    config.severity
                )
            })?;
            let rule = vord_rules_smells::CustomRule::new(
                &config.id,
                &config.message,
                &config.pattern,
                severity,
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[[rules.custom]] {:?} is invalid: `id` must be `namespace:code` lowercase \
                     kebab-case, and `pattern` must be a valid regex (got pattern {:?})",
                    config.id,
                    config.pattern
                )
            })?;
            profile.activate(rule.id().clone(), severity);
            service = service.register_rule(Box::new(rule));
        }
        service = service.with_profile(profile);
    }
    // Cheap (at most tsconfig.json + one `extends` hop) so it's always
    // discovered, unlike `rust_crates` below — resolves TS/JS `@/`-style
    // path-aliased imports for every architecture rule built on
    // `ImportGraph`. Without this, a project whose imports go through such
    // an alias looks like it has almost no import edges at all, silently
    // hiding real cycles/instability/layer violations (`vord arch` shows
    // the same gap for the same reason). An empty result (no tsconfig.json,
    // or no `paths` declared) changes nothing below.
    let ts_aliases = vord_infra_fs::discover_ts_path_aliases(path);
    let boundaries = architecture_config(architecture);
    if !boundaries.is_empty() {
        // Only discovered when there's a boundary to check against — this
        // walks every Cargo.toml under `path`, wasted work for a project
        // with no `[architecture]` table declared.
        let rust_crates = vord_infra_fs::discover_rust_crates(path);
        service = service.register_cross_rule(Box::new(
            vord_rules_architecture::BoundaryViolationRule::new(boundaries, rust_crates)
                .with_ts_aliases(ts_aliases.clone()),
        ));
    }
    if !ts_aliases.is_empty() {
        service = service
            .replace_cross_rule(Box::new(
                vord_rules_architecture::DependencyCycleRule::new()
                    .with_ts_aliases(ts_aliases.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_architecture::MainSequenceRule::default()
                    .with_ts_aliases(ts_aliases.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_architecture::StableDependencyRule::default()
                    .with_ts_aliases(ts_aliases.clone()),
            ));
        if architecture.layer.is_empty() {
            service = service.replace_cross_rule(Box::new(
                vord_rules_architecture::HexagonalLayerRule::new()
                    .with_ts_aliases(ts_aliases.clone()),
            ));
        }
    }
    if !architecture.layer.is_empty() {
        let taxonomy = layer_taxonomy(architecture)?;
        service = service
            .replace_cross_rule(Box::new(
                vord_rules_architecture::HexagonalLayerRule::with_taxonomy(taxonomy.clone())
                    .with_ts_aliases(ts_aliases.clone()),
            ))
            .replace_rule(Box::new(
                vord_rules_architecture::FrameworkInDomainRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_rule(Box::new(
                vord_rules_ddd::PersistenceInDomainRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_rule(Box::new(
                vord_rules_ddd::DomainJargonNamingRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_rule(Box::new(
                vord_rules_ddd::OneAggregatePerTransactionRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::AnemicDomainModelRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::PublicEntitySetterRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::PrimitiveObsessionRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::ExposedCollectionRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::ValueObjectMutationRule::with_taxonomy(taxonomy.clone()),
            ))
            .replace_cross_rule(Box::new(
                vord_rules_ddd::AggregateReferenceByIdRule::with_taxonomy(taxonomy),
            ));
    }
    if let Some(cache) = cache {
        service = service.with_cache(cache);
    }
    Ok(service.analyze_files(&sources).await?)
}

/// Overlays `[duplication]` from `vord.toml` onto the engine defaults —
/// an unset field keeps the default rather than zeroing it.
pub fn duplication_config(
    settings: &vord_infra_fs::DuplicationSettings,
) -> vord_rules_engine::DuplicationConfig {
    let defaults = vord_rules_engine::DuplicationConfig::default();
    vord_rules_engine::DuplicationConfig {
        block_size: settings.block_size.unwrap_or(defaults.block_size),
        min_lines: settings.min_lines.unwrap_or(defaults.min_lines),
        normalization: vord_rules_engine::TokenNormalization {
            identifiers: settings
                .normalize_identifiers
                .unwrap_or(defaults.normalization.identifiers),
        },
        include_test_code: settings
            .include_test_code
            .unwrap_or(defaults.include_test_code),
        max_declarations_spanned: settings
            .max_declarations_spanned
            .unwrap_or(defaults.max_declarations_spanned),
        max_literal_density: settings
            .max_literal_density
            .or(defaults.max_literal_density),
        max_occurrences: settings.max_occurrences.or(defaults.max_occurrences),
    }
}

/// Converts `[architecture]` from `vord.toml` into the engine-facing
/// `vord_import_graph::ArchitectureConfig` `BoundaryViolationRule` takes —
/// same shape of bridge `duplication_config` is for `[duplication]`, just
/// with no defaults to overlay (an empty list stays an empty list; there is
/// nothing to declare a boundary that means "no boundary declared").
pub fn architecture_config(
    settings: &vord_infra_fs::ArchitectureSettings,
) -> vord_import_graph::ArchitectureConfig {
    let edge = |e: &vord_infra_fs::DependencyEdgeConfig| {
        vord_import_graph::DependencyEdge::new(&e.from, &e.to)
    };
    vord_import_graph::ArchitectureConfig {
        allowed_dependencies: settings.allowed_dependencies.iter().map(edge).collect(),
        forbidden_dependencies: settings.forbidden_dependencies.iter().map(edge).collect(),
        exceptions: settings.exceptions.iter().map(edge).collect(),
    }
}

/// Converts `[[architecture.layer]]` from `vord.toml` into the
/// engine-facing `vord_import_graph::LayerTaxonomy` the hexagonal-layer,
/// framework-purity and DDD tactical rules take. Unlike `architecture_config`,
/// this can fail: an unknown `is_a` ring name or an invalid glob pattern must
/// stop the scan with a clear message rather than silently classify nothing.
pub fn layer_taxonomy(
    settings: &vord_infra_fs::ArchitectureSettings,
) -> Result<vord_import_graph::LayerTaxonomy, vord_import_graph::LayerTaxonomyError> {
    let entries = settings
        .layer
        .iter()
        .map(|l| vord_import_graph::CustomLayerSpec {
            name: l.name.clone(),
            is_a: l.is_a.clone(),
            patterns: l.patterns.clone(),
        })
        .collect();
    vord_import_graph::LayerTaxonomy::new(entries)
}

/// Converts `[vite_react.exceptions]` from `vord.toml` into the plain
/// `(rule id, globs)` pairs [`scan_with_profile`] applies — same shape of
/// bridge `architecture_config` is for `[architecture]`, just keyed by rule
/// id instead of a fixed struct, since one glob-exceptions table serves
/// every rule in `rulesets/vite-react` rather than one edge kind.
pub fn vite_react_config(
    settings: &vord_infra_fs::ViteReactSettings,
) -> HashMap<String, Vec<String>> {
    settings.exceptions.clone()
}

/// Reconstructs the one `rulesets/vite-react` rule named `rule_id` with
/// `globs` as its exceptions, or `None` for a rule id this ruleset doesn't
/// recognize (a `vord.toml` typo is ignored here rather than failing the
/// scan — the same forward-compatible posture `ViteReactSettings` itself
/// documents). `service.replace_rule` then swaps it in for the
/// zero-exceptions instance `default_service` already registered.
fn vite_react_rule_with_exceptions(rule_id: &str, globs: Vec<String>) -> Option<Box<dyn Rule>> {
    match rule_id {
        "vite-react:no-data-layer-import-in-view" => Some(Box::new(
            vord_rules_vite_react::NoDataLayerImportInViewRule::with_exceptions(globs),
        )),
        "vite-react:no-transport-call-in-view" => Some(Box::new(
            vord_rules_vite_react::NoTransportCallInViewRule::with_exceptions(globs),
        )),
        "vite-react:data-hook-outside-api-dir" => Some(Box::new(
            vord_rules_vite_react::DataHookOutsideApiDirRule::with_exceptions(globs),
        )),
        "vite-react:transport-client-outside-infra" => Some(Box::new(
            vord_rules_vite_react::TransportClientOutsideInfraRule::with_exceptions(globs),
        )),
        "vite-react:hardcoded-base-url" => Some(Box::new(
            vord_rules_vite_react::HardcodedBaseUrlRule::with_exceptions(globs),
        )),
        "vite-react:tailwind-space-between" => Some(Box::new(
            vord_rules_vite_react::TailwindSpaceBetweenRule::with_exceptions(globs),
        )),
        _ => None,
    }
}

/// Walks up from `start` looking for a `.git` directory, so remediation can
/// sandbox its verification in the real worktree the file lives in rather
/// than mutating the caller's file directly with no rollback.
pub fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Generates and verifies an AI fix for `issue_rule` in `path`, applying it
/// to the real working tree on acceptance (rolled back automatically by the
/// `WorktreeSandbox` if verification fails). Shared by `vord fix` and the
/// interactive wizard so there is exactly one place that applies fixes.
/// Returns the canonicalized path alongside the verdict for the caller to
/// report on.
pub async fn remediate_issue(
    path: &Path,
    issue_rule: &str,
    model: Option<String>,
) -> anyhow::Result<(PathBuf, vord_remediation::RemediationVerdict)> {
    let path = path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let git_root = find_git_root(&path).ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not inside a Git worktree — the Remediation Agent needs one to sandbox and verify the fix",
            path.display()
        )
    })?;

    let source_code = tokio::fs::read_to_string(&path).await?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let language = vord_ast::LanguageIdentifier::from_extension(ext)
        .ok_or_else(|| anyhow::anyhow!("unrecognized file extension for {}", path.display()))?;
    let rel_path = path
        .strip_prefix(&git_root)
        .unwrap_or(&path)
        .to_string_lossy()
        .to_string();
    let source_file = vord_ast::SourceFile::new(rel_path, source_code.clone(), language)
        .map_err(|e| anyhow::anyhow!("invalid file path: {e}"))?;

    let service = default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
    let report = service
        .analyze_files(std::slice::from_ref(&source_file))
        .await?;
    let target_issue = report
        .issues()
        .iter()
        .find(|found| found.rule().as_str() == issue_rule)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no issue for rule '{issue_rule}' found in {}",
                path.display()
            )
        })?;
    let base_url = std::env::var("VORD_LLM_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:11434/v1".to_string());
    let api_key = std::env::var("VORD_LLM_API_KEY").ok();
    let model_name = model.unwrap_or_else(|| {
        std::env::var("VORD_LLM_MODEL").unwrap_or_else(|_| "llama3".to_string())
    });
    let adapter = vord_infra_llm::OpenAiCompatibleAdapter::new(
        base_url,
        model_name,
        api_key.unwrap_or_default(),
    );
    let sandbox = vord_infra_fs::WorktreeSandbox::new(&git_root)?;
    let engine = vord_remediation::RemediationEngine::new(adapter, sandbox);

    let verdict = engine
        .attempt_remediation(&target_issue, &path, &source_code, &service)
        .await?;
    Ok((path, verdict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_rules_have_unique_ids() {
        let rules: Vec<Box<dyn Rule>> = vord_rules_owasp::all_rules()
            .into_iter()
            .chain(vord_rules_smells::all_rules())
            .chain(vord_rules_iac::all_rules())
            .chain(vord_rules_a11y::all_rules())
            .chain(vord_rules_react::all_rules())
            .chain(vord_rules_secrets::all_rules())
            .chain(vord_rules_rust::all_rules())
            .chain(vord_rules_reactive::all_rules())
            .chain(vord_rules_python::all_rules())
            .chain(vord_rules_typescript::all_rules())
            .chain(vord_rules_php::all_rules())
            .chain(vord_rules_wordpress::all_rules())
            .chain(vord_rules_go::all_rules())
            .chain(vord_rules_ai_agent::all_rules())
            .chain(vord_rules_architecture::all_rules())
            .chain(vord_rules_ddd::all_rules())
            .chain(vord_rules_vite_react::all_rules())
            .collect();

        let mut seen = HashSet::new();
        for r in &rules {
            assert!(
                seen.insert(r.id().to_string()),
                "Duplicate rule ID found: {}",
                r.id()
            );
        }
    }

    fn write_fixture(dir: &std::path::Path, relative: &str, content: &str) {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn temp_fixture_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vord-cli-custom-rule-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Proves `[[rules.custom]]` actually fires now — before this was
    /// wired, a `CustomRuleConfig` was parsed from `vord.toml` and then
    /// silently discarded: nothing in `bin/cli` ever constructed a `Rule`
    /// from it, and even a directly `register_rule`-d instance would still
    /// be filtered out by `QualityProfile::is_active` since a user-chosen
    /// id is never pre-listed in the built-in "vord way" profile.
    #[test]
    fn a_configured_custom_rule_actually_fires() {
        let dir = temp_fixture_dir("fires");
        write_fixture(&dir, "a.ts", "console.log('debug');\nexport const x = 1;\n");
        let custom = vec![vord_infra_fs::CustomRuleConfig {
            id: "custom:no-console-log".to_string(),
            message: "Remove console.log before merging".to_string(),
            pattern: r"console\.log\(".to_string(),
            severity: "minor".to_string(),
        }];

        let report = futures::executor::block_on(scan_with_profile(
            &dir,
            None,
            &[],
            &[],
            &[],
            &ProjectSettings {
                duplication: &Default::default(),
                architecture: &Default::default(),
                vite_react: &Default::default(),
                secrets: &Default::default(),
                rules_custom: &custom,
            },
            None,
        ))
        .unwrap();

        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.rule().as_str() == "custom:no-console-log"),
            "expected a custom:no-console-log issue, got: {:?}",
            report
                .issues()
                .iter()
                .map(|i| i.rule().as_str())
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_custom_rules_configured_is_unaffected() {
        let dir = temp_fixture_dir("empty");
        write_fixture(&dir, "a.ts", "console.log('debug');\n");

        let report = futures::executor::block_on(scan_with_profile(
            &dir,
            None,
            &[],
            &[],
            &[],
            &ProjectSettings {
                duplication: &Default::default(),
                architecture: &Default::default(),
                vite_react: &Default::default(),
                secrets: &Default::default(),
                rules_custom: &[],
            },
            None,
        ))
        .unwrap();

        assert!(
            !report
                .issues()
                .iter()
                .any(|i| i.rule().as_str().starts_with("custom:"))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_invalid_custom_rule_pattern_fails_the_scan_loudly() {
        let dir = temp_fixture_dir("bad-pattern");
        write_fixture(&dir, "a.ts", "export const x = 1;\n");
        let custom = vec![vord_infra_fs::CustomRuleConfig {
            id: "custom:broken".to_string(),
            message: "broken".to_string(),
            pattern: "(unclosed".to_string(),
            severity: "major".to_string(),
        }];

        let result = futures::executor::block_on(scan_with_profile(
            &dir,
            None,
            &[],
            &[],
            &[],
            &ProjectSettings {
                duplication: &Default::default(),
                architecture: &Default::default(),
                vite_react: &Default::default(),
                secrets: &Default::default(),
                rules_custom: &custom,
            },
            None,
        ));

        assert!(
            result.is_err(),
            "an invalid regex must fail the scan, not silently do nothing"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unknown_custom_rule_severity_fails_the_scan_loudly() {
        let dir = temp_fixture_dir("bad-severity");
        write_fixture(&dir, "a.ts", "export const x = 1;\n");
        let custom = vec![vord_infra_fs::CustomRuleConfig {
            id: "custom:broken".to_string(),
            message: "broken".to_string(),
            pattern: "x".to_string(),
            severity: "extremely-bad".to_string(),
        }];

        let result = futures::executor::block_on(scan_with_profile(
            &dir,
            None,
            &[],
            &[],
            &[],
            &ProjectSettings {
                duplication: &Default::default(),
                architecture: &Default::default(),
                vite_react: &Default::default(),
                secrets: &Default::default(),
                rules_custom: &custom,
            },
            None,
        ));

        assert!(result.is_err());
    }

    /// Proves `[secrets] ignore_keys` actually reaches
    /// `secrets:high-entropy-string` through `scan_with_profile` — a JSON
    /// value under a declared key is suppressed, while the same shaped
    /// value under any other key still fires.
    #[test]
    fn secrets_ignore_keys_actually_suppresses_the_declared_key() {
        let dir = temp_fixture_dir("secrets-ignore-keys");
        let token = ["aG3n7Zq9L", "m2XpW5vB", "t8FhKc1RdSy"].concat();
        write_fixture(
            &dir,
            "presets.json",
            &format!("{{\"value\": \"{token}\", \"apiKey\": \"{token}\"}}\n"),
        );

        let secrets = vord_infra_fs::SecretsSettings {
            ignore_keys: vec!["value".to_string()],
        };
        let report = futures::executor::block_on(scan_with_profile(
            &dir,
            None,
            &[],
            &[],
            &[],
            &ProjectSettings {
                duplication: &Default::default(),
                architecture: &Default::default(),
                vite_react: &Default::default(),
                secrets: &secrets,
                rules_custom: &[],
            },
            None,
        ))
        .unwrap();

        let entropy_findings: Vec<_> = report
            .issues()
            .iter()
            .filter(|i| i.rule().as_str() == "secrets:high-entropy-string")
            .collect();
        assert_eq!(
            entropy_findings.len(),
            1,
            "expected exactly the apiKey value to still be flagged, got: {entropy_findings:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
