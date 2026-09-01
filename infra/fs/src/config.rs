//! Configuration loader for `vord.toml` / `.vord.toml` and legacy `sonar-project.properties`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct VordConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub duplication: DuplicationSettings,
    #[serde(default)]
    pub architecture: ArchitectureSettings,
    #[serde(default)]
    pub agent: AgentSettings,
    #[serde(default)]
    pub swarm: SwarmSettings,
    #[serde(default)]
    pub gate: GateSettings,
    #[serde(default)]
    pub vite_react: ViteReactSettings,
    #[serde(default)]
    pub secrets: SecretsSettings,
    /// `[[flows]]` — named, explicitly ordered call sequences a human or an
    /// AI agent has registered for `vord scan` to track. The escape hatch
    /// for a flow static call-graph analysis cannot infer on its own
    /// (cross-file, cross-language, dispatched through a router/queue/cron
    /// rather than a direct call) — the same "declare what static analysis
    /// can't reconstruct" role `[[gherkin_required]]` plays in
    /// `vord-policy.toml` for feature-level coverage evidence, but at
    /// function-sequence granularity and evaluated against ingested line
    /// coverage rather than Gherkin tags. Empty by default — no `[[flows]]`
    /// declared means nothing to evaluate, the same opt-in-until-configured
    /// convention `[architecture]` and `[duplication]` already use.
    #[serde(default)]
    pub flows: Vec<FlowConfig>,
}

/// One `[[flows]]` entry: a name (used in the finding message) plus its
/// ordered steps. `vord flow add` appends these; `vord scan` evaluates them
/// once a coverage report has been ingested.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowConfig {
    pub name: String,
    #[serde(default)]
    pub steps: Vec<FlowStepConfig>,
}

/// One step of a `[[flows]]` entry: `path` is repository-relative (the same
/// convention ingested coverage reports and `Issue::file()` already use),
/// `function` is that function's declared name in `path`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowStepConfig {
    pub path: String,
    pub function: String,
}

/// `[gate]` in `vord.toml` — quality-gate thresholds evaluated by
/// `vord scan --enforce-gate` and CI/pre-commit hooks.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateSettings {
    /// Minimum health score (0-100). When set, `vord scan --enforce-gate`
    /// exits with status 3 if the score falls below this value.
    pub min_health_score: Option<u32>,
}

/// `[vite_react]` in `vord.toml` — per-rule glob exceptions for the
/// `vite-react-frontend-starter` profile's own rules (`rulesets/vite-react`).
/// Keyed by the rule's full id (e.g.
/// `"vite-react:no-data-layer-import-in-view"`) so one table can carry
/// exceptions for every rule in the ruleset without a field per rule; a rule
/// id this profile doesn't recognize is ignored rather than rejected, the
/// same forward-compatible posture `[[rules.custom]]` already takes.
/// Empty by default — no exceptions declared means every rule applies
/// everywhere, the same opt-in-until-configured convention `[architecture]`
/// and `[duplication]` already use.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ViteReactSettings {
    #[serde(default)]
    pub exceptions: HashMap<String, Vec<String>>,
}

/// `[secrets]` in `vord.toml` — project-declared tuning for
/// `rulesets/secrets`'s `secrets:high-entropy-string` rule.
///
/// `ignore_keys` names JSON/object key names (case-insensitive) whose
/// values are never flagged, however high their entropy — the surgical
/// escape hatch for a project whose data files legitimately store long
/// encoded blobs (serialized presets, embedded assets, base64 payloads)
/// under a generic key like `"value"`, without having to exclude the whole
/// file or directory via `[analysis] exclusions`. Empty by default — no
/// keys declared means the rule's own built-in heuristics (key-name and
/// length-based confidence) are all that apply, the same
/// opt-in-until-configured convention `[architecture]` and `[duplication]`
/// already use.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretsSettings {
    #[serde(default)]
    pub ignore_keys: Vec<String>,
}

/// `[agent]` in `vord.toml` — the `vord agent` runtime's limits.
///
/// Not to be confused with `[agent]` in **`vord-policy.toml`**, which is the
/// Agent Permission Policy: what an agent may *do*. This table is only what a
/// run may *spend*. They are separate files because they answer to separate
/// people — the policy is a security control a reviewer owns, these are
/// operational knobs whoever runs the agent owns.
///
/// Every field is optional and falls back to `vord_agent`'s own default, so a
/// project states only what it wants changed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSettings {
    /// Model turns one run may take (runtime default 40).
    pub max_turns: Option<u32>,
    /// Tokens one run may spend across all turns (runtime default 500000).
    pub max_tokens: Option<u64>,
    /// How many times the analyzer may send the model back before the run is
    /// reported incomplete (runtime default 3).
    pub max_rejections: Option<u32>,
    /// Programs the `run` tool may execute. Replaces the built-in list
    /// outright rather than extending it — an allowlist you have to read two
    /// places to understand is not one.
    pub allowed_commands: Option<Vec<String>>,
    /// Wall-clock seconds a `run` command may take before it is killed
    /// (adapter default 300).
    pub command_timeout_secs: Option<u64>,
}

/// `[swarm]` in `vord.toml` — worktree-per-agent isolation and role config
/// for `vord swarm` (roadmap B1). Every role gets its own git worktree so
/// concurrent agents never contend on the index, and its own [`RoleScope`]
/// policy narrowing (roadmap B3) so a role's access is scoped to what it
/// actually needs — the cleaner may not touch `.github/workflows/**`, QA
/// gets no write access at all.
///
/// Absent (or with no `[[swarm.role]]` entries) means `vord swarm` has
/// nothing configured to run — the same opt-in-until-configured convention
/// `[architecture]` and `[duplication]` already use.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwarmSettings {
    /// Directory (repository-relative) worktrees are created under.
    /// Defaults to `.vord/worktrees` when unset.
    pub worktree_root: Option<String>,
    #[serde(default, rename = "role")]
    pub roles: Vec<RoleSettings>,
    /// A named pipeline shape (roadmap B4): `"two-pack"` (coder, reviewer) or
    /// `"four-pack"` (architect, coder, cleaner, qa), each name expected to
    /// match a configured role's own `name`. Ignored when `pipeline` is set.
    pub topology: Option<String>,
    /// An explicit, ordered role-name pipeline — outranks `topology` the same
    /// way a CLI flag outranks `vord.toml` elsewhere in this file, since it
    /// says exactly what the operator wants rather than naming a preset.
    pub pipeline: Option<Vec<String>>,
}

/// One `[[swarm.role]]` entry: a named role, its own worktree/branch naming,
/// and the access restrictions layered onto the base `vord-policy.toml` for
/// writes made from inside that role's worktree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleSettings {
    pub name: String,
    /// Worktree directory for this role, relative to `worktree_root`.
    /// Defaults to the role's own `name` when unset.
    pub worktree: Option<String>,
    /// Branch the worktree is created on. Defaults to `vord/swarm/<name>`
    /// when unset.
    pub branch: Option<String>,
    /// Extra paths this role may never write to, beyond the base policy's
    /// own `[[protected_path]]` entries.
    #[serde(default)]
    pub protected_paths: Vec<RoleProtectedPath>,
    /// Extra rule ids this role may never introduce, beyond the base
    /// policy's `blocking_rules`.
    #[serde(default)]
    pub blocking_rules: Vec<String>,
    /// Extra rule ids this role's writes escalate to, beyond the base
    /// policy's `escalate_rules`.
    #[serde(default)]
    pub escalate_rules: Vec<String>,
}

/// Same shape as `vord-policy.toml`'s `[[protected_path]]`, declared inline
/// under a role instead of in the policy file — a role's scope lives beside
/// its other settings in `vord.toml`, not split across two files.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleProtectedPath {
    pub pattern: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    pub key: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub sources: Option<Vec<String>>,
    pub exclusions: Option<Vec<String>>,
    pub inclusions: Option<Vec<String>>,
    pub profile: Option<String>,
}

/// `[duplication]` in `vord.toml`. Every field is optional and falls back
/// to the engine default, so a project only states what it wants changed.
/// These were hardcoded before, which meant a codebase whose shape did not
/// suit the defaults had no recourse.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DuplicationSettings {
    /// Smallest clone worth reporting, in source lines (engine default 10).
    pub min_lines: Option<usize>,
    /// Consecutive statements per hashed block (engine default 5) — the
    /// granularity candidate matches are found at, before extension.
    pub block_size: Option<usize>,
    /// Erase identifier names before hashing, so a copied-and-renamed block
    /// still matches ("Type-2" clones). Off by default.
    pub normalize_identifiers: Option<bool>,
    /// Let test code participate in duplication detection. Off by default —
    /// repetition in a test suite is usually deliberate.
    pub include_test_code: Option<bool>,
    /// Most declaration boundaries one reported clone may span (engine
    /// default 1). Raise it to see regions that cover several adjacent
    /// declarations, e.g. a whole trait implementation.
    pub max_declarations_spanned: Option<usize>,
    /// When `Some(d)`, suppress clone sets whose token stream is at least
    /// fraction `d` literal placeholders (`\0STR\0`, `\0NUM\0`) — the match
    /// is a lookup table rather than copied logic worth refactoring. Passed
    /// straight through to `DuplicationConfig::max_literal_density`.
    /// Default: `Some(0.25)`.
    pub max_literal_density: Option<f32>,
    /// When `Some(n)`, suppress clone sets with more than `n` occurrences —
    /// the match is structural boilerplate (e.g. closing braces shared by
    /// every `Rule::check` implementation), not copied logic worth
    /// refactoring. Passed straight through to
    /// `DuplicationConfig::max_occurrences`. Default: `Some(8)`.
    pub max_occurrences: Option<usize>,
}

/// `[architecture]` in `vord.toml` — declared component boundaries (roadmap
/// D2). Components are derived automatically from directory topology
/// (`vord_import_graph::component_of`, roadmap D1), so there is nothing to
/// declare here except the edges themselves. All three lists default to
/// empty, meaning no boundaries declared — the architecture rule is then a
/// silent no-op, the same fail-open convention `[duplication]` follows.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchitectureSettings {
    /// Once non-empty, switches the check into whitelist mode: any
    /// component-level edge not listed here is a violation.
    #[serde(default)]
    pub allowed_dependencies: Vec<DependencyEdgeConfig>,
    /// Component-level edges that are always a violation, regardless of
    /// `allowed_dependencies`.
    #[serde(default)]
    pub forbidden_dependencies: Vec<DependencyEdgeConfig>,
    /// Specific edges exempted from both lists above — the escape hatch for
    /// a deliberate, reviewed exception to an otherwise-general rule.
    #[serde(default)]
    pub exceptions: Vec<DependencyEdgeConfig>,
    /// Project-specific layer names that play the role of one of the five
    /// built-in hexagonal rings (`domain`/`application`/`port`/`adapter`/
    /// `infrastructure`), so `architecture:hexagonal-layer-violation`,
    /// `architecture:framework-in-domain` and the `rulesets/ddd` tactical
    /// rules recognize a directory like `checkout/` as domain code without
    /// renaming it to `domain/`. Empty by default — the same zero-config
    /// behavior as today.
    #[serde(default)]
    pub layer: Vec<LayerConfig>,
}

/// One `{ from = "...", to = "..." }` entry in an `[architecture]` list.
/// `from`/`to` name a component (`component_of`'s output, e.g.
/// `"core/rules-engine"`) or a whole tier with no component-name segment
/// (e.g. `"core"`, matching every component under it) — see
/// `vord_import_graph::DependencyEdge` for the matching rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyEdgeConfig {
    pub from: String,
    pub to: String,
}

/// One `[[architecture.layer]]` entry: `name` is documentation only (it
/// appears in validation errors), `is_a` names the built-in ring this layer
/// subsumes into, and `patterns` are the globs (matched against a file's
/// path, same syntax `[[protected_path]]` in `vord-policy.toml` already
/// uses) that mark a path as belonging to it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayerConfig {
    pub name: String,
    pub is_a: String,
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// `[rules]` in `vord.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    #[serde(default)]
    pub custom: Vec<CustomRuleConfig>,
}

/// One `[[rules.custom]]` entry: a project-declared regex rule, for a
/// convention vord has no built-in rule for. `bin/cli` builds a
/// `vord_rules_smells::CustomRule` from each entry and activates it
/// explicitly on top of whatever quality profile is otherwise in effect —
/// a user-chosen `id` can never be pre-listed in the built-in "vord way"
/// profile, so it would never fire through the ordinary registration path
/// alone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomRuleConfig {
    /// `namespace:code` in lowercase kebab-case (e.g. `"custom:no-console-log"`),
    /// the same format every built-in rule id uses. An invalid id fails
    /// the scan at startup rather than being silently dropped.
    pub id: String,
    /// The finding message shown for every match.
    pub message: String,
    /// A real regex (not a literal substring), matched independently
    /// against each line of every scanned file — a match anywhere on a
    /// line reports that whole line. An invalid regex fails the scan at
    /// startup rather than being silently dropped.
    pub pattern: String,
    /// `info`/`minor`/`major`/`critical`/`blocker`, case-insensitive.
    /// Defaults to `"major"`. An unrecognized value fails the scan at
    /// startup.
    #[serde(default = "default_severity_str")]
    pub severity: String,
}

fn default_severity_str() -> String {
    "major".to_string()
}

impl VordConfig {
    /// Attempts to load configuration from `vord.toml`, `.vord.toml`, or `sonar-project.properties`.
    pub fn load_from_dir(dir: &Path) -> Option<Self> {
        let vord_toml = dir.join("vord.toml");
        if vord_toml.exists() {
            if let Ok(content) = fs::read_to_string(&vord_toml) {
                if let Ok(config) = toml::from_str::<VordConfig>(&content) {
                    return Some(config);
                }
            }
        }

        let dot_vord_toml = dir.join(".vord.toml");
        if dot_vord_toml.exists() {
            if let Ok(content) = fs::read_to_string(&dot_vord_toml) {
                if let Ok(config) = toml::from_str::<VordConfig>(&content) {
                    return Some(config);
                }
            }
        }

        let sonar_props = dir.join("sonar-project.properties");
        if sonar_props.exists() {
            if let Ok(content) = fs::read_to_string(&sonar_props) {
                return Some(Self::parse_sonar_properties(&content));
            }
        }

        None
    }

    pub fn parse_sonar_properties(content: &str) -> Self {
        let mut config = VordConfig::default();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                apply_sonar_property(&mut config, key.trim(), val.trim());
            }
        }
        config
    }
}

/// Splits a comma-joined `sonar.*` property value (`"src,lib"`) into its
/// trimmed parts.
fn split_csv(val: &str) -> Vec<String> {
    val.split(',').map(|s| s.trim().to_string()).collect()
}

fn apply_sonar_property(config: &mut VordConfig, key: &str, val: &str) {
    match key {
        "sonar.projectKey" => config.project.key = Some(val.to_string()),
        "sonar.projectName" => config.project.name = Some(val.to_string()),
        "sonar.projectVersion" => config.project.version = Some(val.to_string()),
        "sonar.sources" => config.analysis.sources = Some(split_csv(val)),
        "sonar.exclusions" => config.analysis.exclusions = Some(split_csv(val)),
        "sonar.inclusions" => config.analysis.inclusions = Some(split_csv(val)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vord_toml_with_custom_rules() {
        let toml_content = r#"
[project]
key = "my-awesome-repo"
name = "My Awesome Repository"
version = "1.2.3"

[analysis]
sources = ["src", "lib"]

[[rules.custom]]
id = "custom:no-console-log"
message = "Do not leave console.log in production code"
pattern = "console.log"
severity = "minor"
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.project.key.as_deref(), Some("my-awesome-repo"));
        assert_eq!(config.rules.custom.len(), 1);
        assert_eq!(config.rules.custom[0].pattern, "console.log");
        assert!(config.architecture.forbidden_dependencies.is_empty());
    }

    #[test]
    fn parses_sonar_properties() {
        let props = r#"
# Sonar project configuration
sonar.projectKey=legacy-sonar-key
sonar.projectName=Legacy App
sonar.sources=src,lib
sonar.exclusions=**/vendor/**
"#;
        let config = VordConfig::parse_sonar_properties(props);
        assert_eq!(config.project.key.as_deref(), Some("legacy-sonar-key"));
        assert_eq!(config.project.name.as_deref(), Some("Legacy App"));
        assert_eq!(config.analysis.sources.unwrap(), vec!["src", "lib"]);
    }

    #[test]
    fn parses_architecture_boundaries() {
        let toml_content = r#"
[[architecture.allowed_dependencies]]
from = "bin"
to = "core"

[[architecture.forbidden_dependencies]]
from = "core"
to = "infra"

[[architecture.exceptions]]
from = "core/legacy"
to = "infra"
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.architecture.allowed_dependencies.len(), 1);
        assert_eq!(config.architecture.allowed_dependencies[0].from, "bin");
        assert_eq!(config.architecture.forbidden_dependencies[0].to, "infra");
        assert_eq!(config.architecture.exceptions[0].from, "core/legacy");
    }

    #[test]
    fn architecture_table_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.architecture, ArchitectureSettings::default());
    }

    #[test]
    fn parses_a_declared_layer_taxonomy() {
        let toml_content = r#"
[[architecture.layer]]
name = "checkout-domain"
is_a = "domain"
patterns = ["src/checkout/**", "src/billing/core/**"]
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.architecture.layer.len(), 1);
        assert_eq!(config.architecture.layer[0].name, "checkout-domain");
        assert_eq!(config.architecture.layer[0].is_a, "domain");
        assert_eq!(
            config.architecture.layer[0].patterns,
            vec!["src/checkout/**", "src/billing/core/**"]
        );
    }

    #[test]
    fn parses_the_agent_runtime_limits() {
        let toml_content = r#"
[agent]
max_turns = 12
max_tokens = 250000
allowed_commands = ["cargo", "just"]
command_timeout_secs = 60
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.agent.max_turns, Some(12));
        assert_eq!(config.agent.max_tokens, Some(250_000));
        assert_eq!(
            config.agent.allowed_commands.as_deref(),
            Some(["cargo".to_string(), "just".to_string()].as_slice())
        );
        assert_eq!(config.agent.command_timeout_secs, Some(60));
        assert_eq!(
            config.agent.max_rejections, None,
            "an unset field stays unset rather than defaulting to zero"
        );
    }

    #[test]
    fn the_agent_table_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.agent, AgentSettings::default());
    }

    #[test]
    fn parses_swarm_roles() {
        let toml_content = r#"
[swarm]
worktree_root = ".vord/worktrees"

[[swarm.role]]
name = "coder"

[[swarm.role]]
name = "qa"
branch = "vord/swarm/qa-custom"
blocking_rules = ["owasp:eval-usage"]
escalate_rules = ["smells:god-class"]

[[swarm.role.protected_paths]]
pattern = "**"
reason = "QA is read-only"
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(
            config.swarm.worktree_root.as_deref(),
            Some(".vord/worktrees")
        );
        assert_eq!(config.swarm.roles.len(), 2);
        assert_eq!(config.swarm.roles[0].name, "coder");
        assert!(config.swarm.roles[0].protected_paths.is_empty());
        let qa = &config.swarm.roles[1];
        assert_eq!(qa.name, "qa");
        assert_eq!(qa.branch.as_deref(), Some("vord/swarm/qa-custom"));
        assert_eq!(qa.blocking_rules, vec!["owasp:eval-usage".to_string()]);
        assert_eq!(qa.escalate_rules, vec!["smells:god-class".to_string()]);
        assert_eq!(qa.protected_paths.len(), 1);
        assert_eq!(qa.protected_paths[0].pattern, "**");
    }

    #[test]
    fn the_swarm_table_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.swarm, SwarmSettings::default());
        assert!(config.swarm.roles.is_empty());
    }

    #[test]
    fn parses_vite_react_exceptions() {
        let toml_content = r#"
[vite_react.exceptions]
"vite-react:no-data-layer-import-in-view" = ["src/components/LegacyWidget/**"]
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(
            config
                .vite_react
                .exceptions
                .get("vite-react:no-data-layer-import-in-view")
                .map(Vec::as_slice),
            Some(["src/components/LegacyWidget/**".to_string()].as_slice())
        );
    }

    #[test]
    fn the_vite_react_table_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.vite_react, ViteReactSettings::default());
        assert!(config.vite_react.exceptions.is_empty());
    }

    #[test]
    fn parses_secrets_ignore_keys() {
        let toml_content = r#"
[secrets]
ignore_keys = ["value", "preset", "payload"]
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(
            config.secrets.ignore_keys,
            vec!["value".to_string(), "preset".to_string(), "payload".to_string()]
        );
    }

    #[test]
    fn the_secrets_table_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.secrets, SecretsSettings::default());
        assert!(config.secrets.ignore_keys.is_empty());
    }

    #[test]
    fn parses_registered_flows() {
        let toml_content = r#"
[[flows]]
name = "checkout-happy-path"

  [[flows.steps]]
  path = "src/checkout.ts"
  function = "startCheckout"

  [[flows.steps]]
  path = "src/payment.ts"
  function = "chargeCard"
"#;
        let config: VordConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.flows.len(), 1);
        let flow = &config.flows[0];
        assert_eq!(flow.name, "checkout-happy-path");
        assert_eq!(flow.steps.len(), 2);
        assert_eq!(flow.steps[0].path, "src/checkout.ts");
        assert_eq!(flow.steps[0].function, "startCheckout");
        assert_eq!(flow.steps[1].path, "src/payment.ts");
        assert_eq!(flow.steps[1].function, "chargeCard");
    }

    #[test]
    fn the_flows_list_is_optional() {
        let config: VordConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert!(config.flows.is_empty());
    }
}
