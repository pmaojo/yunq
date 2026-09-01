//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use vord_cli::output;
use vord_infra_fs::{BaselineStore, FileAnalysisCache};
use vord_rules_engine::{Baseline, NewCodeAnalysis, Severity};

mod arch;
mod blame;
mod ci_detect;
mod crap;
mod flow;
mod hook_install;
mod kickoff;
mod mcp;
mod monorepo_scan;
mod tui;
mod wizard;

#[derive(Parser)]
#[command(name = "vord", about = "vord static analysis", version)]
struct Cli {
    /// No subcommand launches the interactive wizard in a TTY.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a directory or file and report issues.
    // Boxed: `ScanArgs` is far larger than every other variant, so leaving it
    // inline would size the whole enum (and every `Option<Command>`) to its
    // largest member.
    Scan(Box<ScanArgs>),
    /// Generate an AI remediation fix for a target issue or file.
    Fix {
        /// File path containing the issue to fix.
        path: PathBuf,
        /// Issue ID / Rule ID to propose a fix for.
        #[arg(long)]
        issue: String,
        /// Model name for OpenAI-compatible LLM endpoint (e.g. gpt-4o, ollama/llama3).
        #[arg(long)]
        model: Option<String>,
    },
    /// Launch the interactive wizard (same as running `vord` with no subcommand).
    Wizard,
    /// Install the vord GitHub Action workflow into this repository.
    Init {
        /// Write the workflow without asking for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Agentic guardrail: gate an autonomous agent's writes against the
    /// Agent Permission Policy (`vord-policy.toml`).
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// vord's own coding agent: edits this repository under the same policy
    /// `vord hook` enforces on third-party agents, and reports a task
    /// complete only when the analyzer agrees.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Multi-agent orchestration: worktree-per-role isolation, per-role
    /// policy scoping and durable handoffs (roadmap B).
    Swarm {
        #[command(subcommand)]
        action: SwarmAction,
    },
    /// Issue Triage Factory: drive a GitHub issue through reproduce →
    /// diagnose → fix, one step at a time (roadmap C).
    Triage {
        #[command(subcommand)]
        action: TriageAction,
    },
    /// Register or evaluate `[[flows]]`: named call sequences to track for
    /// end-to-end test coverage, beyond what a single function's own
    /// coverage percentage can say.
    Flow {
        #[command(subcommand)]
        action: FlowAction,
    },
    /// Kickoff a new project template for AI-driven development.
    Kickoff {
        /// Template name (react-bulletproof, rust-clean, python-clean, typescript-clean, fullstack-hexagonal).
        #[arg(default_value = "react-bulletproof")]
        template: String,
        /// Target directory.
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
    /// Visualize the component architecture of a directory: import graph
    /// collapsed to components, Martin's Ca/Ce/I/A/D metrics, dependency
    /// cycles. Renders text, Mermaid, JSON, or a self-contained interactive
    /// HTML viewer (`--html arch.html`).
    Arch {
        /// Directory to analyze (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format: text, mermaid or json (default: text).
        #[arg(long, value_enum, default_value = "text")]
        format: ArchFormat,
        /// Write a self-contained interactive HTML viewer to this path.
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Start the Model Context Protocol (MCP) JSON-RPC stdio server.
    Mcp,
}

#[derive(Clone, Copy, ValueEnum)]
enum ArchFormat {
    Text,
    Mermaid,
    Json,
}

#[derive(Subcommand)]
enum AgentAction {
    /// Run one headless session against a task. Exits 0 (the analyzer agrees),
    /// 3 (incomplete), 4 (budget exhausted), 5 (circuit breaker tripped),
    /// 6 (the agent looped) or 1 (vord itself failed).
    Run {
        /// What the agent should do.
        #[arg(long)]
        task: String,
        /// Path the analyzer takes its baseline over and re-scans to decide
        /// completion.
        #[arg(long, default_value = ".")]
        scope: String,
        /// A rule the task must eliminate; the task cannot complete while it
        /// still fires anywhere in scope.
        #[arg(long)]
        rule: Option<String>,
        /// Model turns this run may take (overrides `vord.toml`'s `[agent]`).
        #[arg(long)]
        max_turns: Option<u32>,
        /// Tokens this run may spend (overrides `vord.toml`'s `[agent]`).
        #[arg(long)]
        max_tokens: Option<u64>,
        /// Model name, overriding the provider's configured default.
        #[arg(long)]
        model: Option<String>,
    },
    /// Same as `run`, with a live terminal view of the session attached
    /// (roadmap A6). A spectator, not a second control path: quitting the
    /// view (`q`/`Esc`/`Ctrl-C`) detaches rather than cancels — the run
    /// keeps going headless. Same exit codes as `run`.
    Tui {
        #[arg(long)]
        task: String,
        #[arg(long, default_value = ".")]
        scope: String,
        #[arg(long)]
        rule: Option<String>,
        #[arg(long)]
        max_turns: Option<u32>,
        #[arg(long)]
        max_tokens: Option<u64>,
        #[arg(long)]
        model: Option<String>,
    },
    /// Wait out the late-feedback window on a pull request: poll with
    /// backoff, collect one review batch as one batch, and report quiet, new
    /// feedback, a bot all-clear, or inconclusive. Exits 0 (quiet or
    /// all-clear), 3 (new feedback to triage) or 1 (could not look).
    WatchPr {
        /// Pull request number.
        #[arg(long)]
        pr: u64,
        /// `owner/repo`; defaults to `GITHUB_REPOSITORY`.
        #[arg(long)]
        repo: Option<String>,
        /// Total seconds to keep watching before calling it quiet.
        #[arg(long)]
        window_secs: Option<u64>,
    },
}

#[derive(Subcommand)]
enum SwarmAction {
    /// List every role declared under `[[swarm.role]]` in `vord.toml`, with
    /// its resolved worktree/branch and how much it adds on top of the base
    /// policy.
    Roles,
    /// Create a role's worktree (`git worktree add`), branching from
    /// `--base`.
    WorktreeCreate {
        /// The role's `name`, as declared in `vord.toml`.
        #[arg(long)]
        role: String,
        /// Ref to branch from.
        #[arg(long, default_value = "HEAD")]
        base: String,
    },
    /// Remove a role's worktree (`git worktree remove`).
    WorktreeRemove {
        #[arg(long)]
        role: String,
        /// Remove even with uncommitted changes in the worktree.
        #[arg(long)]
        force: bool,
    },
    /// List every worktree currently registered against this repository
    /// (`git worktree list`) — not only ones `vord swarm` created.
    WorktreeList,
    /// Write a handoff to the sender's outbox.
    HandoffSend {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        summary: String,
    },
    /// Move every outbox handoff into its recipient's inbox, quarantining
    /// anything that fails to parse into `.vord/handoffs/failed/`.
    HandoffDeliver,
    /// List the handoffs currently waiting in a role's inbox.
    HandoffInbox {
        #[arg(long)]
        role: String,
    },
    /// Acknowledge a handoff: move it from the role's inbox to `sent/`.
    HandoffAck {
        #[arg(long)]
        role: String,
        #[arg(long)]
        id: String,
    },
    /// Drive every role in the configured topology (`[swarm] topology =
    /// "two-pack"/"four-pack"`, or an explicit `pipeline`) through one
    /// headless `vord agent` run apiece, in order — each under its own
    /// worktree and scoped policy, each handing the next role a summary of
    /// what it did (roadmap B4). Exits with the exit code of the role whose
    /// run stopped the pipeline, or 0 if every role completed.
    Run {
        /// What the topology as a whole should accomplish; each role's task
        /// is this plus its own name and whatever the previous role handed
        /// off.
        #[arg(long)]
        task: String,
    },
    /// Interactive spec-driven Swarm & Worktree Ratatui Dashboard (Offline / LLM-less).
    Tui,
}

#[derive(Subcommand)]
enum TriageAction {
    /// Advance one GitHub issue by exactly one Issue Triage Factory step
    /// (roadmap C — `docs/design/issue-triage-factory.md`): reads its
    /// current `triage:*` label, does whatever that label calls for, and
    /// writes the resulting label back. Re-run for the next step — this
    /// never advances more than one at a time.
    Advance {
        /// The GitHub issue number.
        #[arg(long)]
        issue: u64,
        /// Required while the issue is `triage:reproducing` or
        /// `triage:fixing`: the shell command that reproduces the reported
        /// bug, run via `sh -c` in the `reproducer`/`fixer` role's
        /// worktree — to classify a repro attempt, or to verify a fix now
        /// makes it pass.
        #[arg(long)]
        repro_command: Option<String>,
    },
}

#[derive(Subcommand)]
enum FlowAction {
    /// Register a named call sequence in `vord.toml` for `vord scan` to
    /// track — the manual escape hatch for a flow static call-graph
    /// analysis can't infer on its own (cross-file, cross-language, or
    /// dispatched through a router/queue/cron rather than a direct call).
    /// An agent that has just identified such a sequence calls this once,
    /// instead of hand-editing TOML; a second `scan` then reports whether
    /// every step is actually exercised, once coverage has been ingested.
    Add {
        /// Flow name, used in the finding message when a step turns out
        /// untested.
        #[arg(long)]
        name: String,
        /// One step per flag, earliest first, as `path:function` — e.g.
        /// `--step src/checkout.ts:startCheckout --step src/payment.ts:chargeCard`.
        #[arg(long = "step", required = true)]
        steps: Vec<String>,
        /// Directory containing (or to receive) `vord.toml`.
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Claude Code hook entry point. Reads the hook payload on stdin and
    /// writes its verdict as JSON on stdout — not run by hand; `vord hook
    /// install` wires it into `.claude/settings.json`.
    ClaudeCode,
    /// Judge one file against the policy. The host-agnostic entry point, for
    /// hosts without file-write hooks (Codex CLI), `pre-commit`, and CI.
    /// Exits 0 (allowed), 2 (denied by policy) or 1 (vord itself failed).
    Check {
        /// File to judge, as the agent would write it.
        file: PathBuf,
        /// `text` prints prose to stderr (the default); `json` prints the structured verdict to
        /// stdout for automated callers.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Wire the guardrail into this repository: write `vord-policy.toml` and
    /// merge the hooks into `.claude/settings.json`.
    Install {
        /// Override the command the hooks invoke (defaults to `vord hook
        /// claude-code`, which must be on PATH).
        #[arg(long)]
        command: Option<String>,
    },
    /// Clear the circuit breaker's persisted per-rule failure counts — the human-intervention
    /// step after a trip. Review what the agent could not resolve, then run this before letting
    /// it continue.
    ResetCircuitBreaker,
    /// Approve an escalated write after human review — the token comes from the denial text or
    /// `hook check --format json`'s `escalation_token` field. Single-use: it authorizes exactly
    /// one retry of the identical write, not a standing exemption for the rule.
    Approve {
        /// The escalation token to approve.
        token: String,
    },
    /// Clear the loop alarm's persisted "last write" streak — the human-intervention step after
    /// a trip, same shape as `reset-circuit-breaker`.
    ResetLoopGuard,
    /// Show the audit log of every non-silent verdict this guardrail has issued
    /// (`.vord-audit.jsonl`).
    Audit {
        /// Show only the most recent N entries.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// `text` prints one line per entry (the default); `json` prints the raw entries as a
        /// JSON array.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
}

#[derive(clap::Args)]
struct CoverageArgs {
    /// LCOV coverage report to ingest (enables the coverage gate condition).
    #[arg(long)]
    coverage: Option<PathBuf>,
    /// Cobertura XML coverage report to ingest.
    #[arg(long)]
    cobertura: Option<PathBuf>,
    /// JaCoCo XML coverage report to ingest.
    #[arg(long)]
    jacoco: Option<PathBuf>,
    /// llvm-cov JSON export coverage report to ingest.
    #[arg(long = "llvm-cov")]
    llvm_cov: Option<PathBuf>,
    /// Istanbul native JSON coverage report (`coverage-final.json`) to ingest.
    #[arg(long)]
    istanbul: Option<PathBuf>,
    /// Coverage report in any supported format (LCOV, Cobertura, JaCoCo,
    /// llvm-cov, Istanbul), auto-detected from content unless
    /// `--coverage-format` is given.
    #[arg(long)]
    coverage_report: Option<PathBuf>,
    /// Format for `--coverage-report` (lcov|cobertura|jacoco|llvm-cov|istanbul).
    /// Auto-detected when omitted.
    #[arg(long)]
    coverage_format: Option<String>,
    /// Unified diff (e.g. `git diff <ref>...HEAD --unified=0`) naming the
    /// "new" lines coverage is restricted to for the coverage-on-new-code
    /// measure. Only takes effect when a coverage report is also given.
    #[arg(long)]
    coverage_diff: Option<PathBuf>,
}

#[derive(clap::Args)]
struct GithubArgs {
    /// Git commit SHA for reporting ALM commit status (auto-detected from
    /// CI env vars — GitHub Actions/GitLab CI — when omitted).
    #[arg(long)]
    commit_sha: Option<String>,
    /// GitHub API token (defaults to GITHUB_TOKEN env var).
    #[arg(long)]
    github_token: Option<String>,
    /// GitHub repository in owner/repo format (defaults to GITHUB_REPOSITORY
    /// env var, or CI auto-detection).
    #[arg(long)]
    github_repo: Option<String>,
    /// Pull/merge request number this analysis is for — marks this as a PR
    /// analysis for ALM status reporting (auto-detected from CI env vars,
    /// e.g. GitHub Actions' `GITHUB_REF`/event payload or GitLab CI's
    /// `CI_MERGE_REQUEST_IID`, when omitted).
    #[arg(long)]
    pr: Option<u32>,
}

/// Reports produced by *other* tools that this scan folds in. Grouped
/// because they share one shape — an optional path to a file vord parses
/// but never generates — and one lifecycle: read after the analysis, merged
/// into the same report, surfaced through the same gate. `CoverageArgs` is
/// the fourth member of this family, kept separate only because coverage
/// alone spans eight flags.
#[derive(clap::Args)]
struct ReportArgs {
    /// JUnit XML test report to ingest (printed as a test summary).
    #[arg(long)]
    junit: Option<PathBuf>,
    /// Mutation-testing report to ingest (Stryker's Mutation Testing
    /// Elements JSON schema — StrykerJS, Stryker.NET, or Infection exported
    /// in that format). Enables the `mutation_score` measure and gate
    /// condition; vord runs no mutants itself, it only aggregates the
    /// verdicts another tool already produced.
    #[arg(long = "mutation-report")]
    mutation_report: Option<PathBuf>,
    /// SARIF 2.x report from another analyzer (ruff, ESLint, clippy, gosec,
    /// bandit, semgrep, CodeQL, …) whose findings are merged into this
    /// scan's issues — they count toward the severity totals and the
    /// quality gate exactly like vord's own. Repeatable.
    #[arg(long, value_name = "PATH")]
    sarif: Vec<PathBuf>,
}

/// Which project(s) the scanned path resolves to, and what to label the
/// results with. These three decide the *identity* of what is being
/// measured — `--monorepo` because it turns one path into many projects,
/// each of which then needs its own key and branch the same way.
#[derive(clap::Args)]
struct ProjectScopeArgs {
    /// Explicit project identifier (defaults to vord.toml's `[project] key`,
    /// then the scanned directory's name).
    #[arg(long)]
    project: Option<String>,
    /// Branch this analysis is attached to (auto-detected from CI env vars
    /// when omitted).
    #[arg(long)]
    branch: Option<String>,
    /// Treat `path` as a monorepo root: discover every vord.toml-configured
    /// project under it and scan each independently, reporting results per
    /// project instead of merging them into one report.
    #[arg(long)]
    monorepo: bool,
}

/// Where the findings go once the analysis is done — none of these change
/// what gets analyzed or whether the scan passes, only what is emitted.
#[derive(clap::Args)]
struct OutputArgs {
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Print a ready-to-paste prompt handing the findings to an AI coding agent.
    #[arg(long)]
    agent_prompt: bool,
    /// Capture per-line SCM blame (author/commit) for files with issues and
    /// write it as JSON to this path — consumable by anything that wants to
    /// show "who introduced this" alongside an issue.
    #[arg(long)]
    blame_output: Option<PathBuf>,
    /// Write an OWASP Top 10 / CWE / PCI DSS compliance report (quality gate
    /// status, vulnerability and hotspot totals, up to 20 findings) as a
    /// PDF 1.4 document to this path.
    #[arg(long)]
    compliance_pdf: Option<PathBuf>,
    /// Write the same compliance evidence as CSV (rule id, severity, file,
    /// line, message — one row per issue) to this path.
    #[arg(long)]
    compliance_csv: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ScanArgs {
    path: PathBuf,
    /// Exit with a non-zero status if any issue at or above this severity is found.
    #[arg(long)]
    fail_on: Option<String>,
    /// Disable the incremental analysis cache (.vord-cache.json).
    #[arg(long)]
    no_cache: bool,
    /// Exit with status 3 when the quality gate fails.
    #[arg(long)]
    enforce_gate: bool,
    /// Exit with status 3 when the health score is below this threshold (0-100).
    /// Requires `--enforce-gate`; ignored otherwise. Defaults to the value
    /// in vord.toml's `[gate] min_health_score` when omitted.
    #[arg(long)]
    min_health_score: Option<u32>,
    /// Do not read or update the New Code baseline (.vord-baseline.json).
    #[arg(long)]
    no_baseline: bool,
    /// List issues tracked in the previous baseline that no longer appear
    /// in this scan, alongside the usual new-issue summary. Requires the
    /// baseline (ignored with `--no-baseline`, and empty on a project's
    /// first scan since there is nothing yet to have resolved).
    #[arg(long)]
    show_resolved: bool,
    /// Quality profile to scan with, by name (e.g. `vite-react-frontend-starter`).
    /// Omitted keeps today's behavior exactly: the built-in "vord way"
    /// profile. Also selects the matching quality gate for `--enforce-gate`
    /// (`vord_cli::quality_gate_for_profile`).
    #[arg(long)]
    profile: Option<String>,
    #[command(flatten)]
    coverage: CoverageArgs,
    #[command(flatten)]
    reports: ReportArgs,
    #[command(flatten)]
    github: GithubArgs,
    #[command(flatten)]
    scope: ProjectScopeArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

/// `vord flow add`: parses each `--step path:function` (splitting on the
/// last `:`, since a function name never contains one) and registers the
/// flow via `flow::register`.
fn run_flow(action: FlowAction) -> anyhow::Result<ExitCode> {
    match action {
        FlowAction::Add { name, steps, path } => {
            let parsed: Vec<(String, String)> = steps
                .iter()
                .map(|step| {
                    step.rsplit_once(':')
                        .map(|(file, function)| (file.to_string(), function.to_string()))
                        .ok_or_else(|| anyhow::anyhow!("--step {step:?} must be `path:function`"))
                })
                .collect::<anyhow::Result<_>>()?;
            flow::register(&path, &name, &parsed)?;
            println!(
                "registered flow {name:?} with {} step(s) in {}",
                parsed.len(),
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        None | Some(Command::Wizard) => wizard::run().await,
        Some(Command::Init { yes }) => wizard::install_ci(&std::env::current_dir()?, yes),
        Some(Command::Scan(args)) => run_scan(*args).await,
        Some(Command::Fix { path, issue, model }) => run_fix(path, issue, model).await,
        Some(Command::Hook { action }) => run_hook(action).await,
        Some(Command::Flow { action }) => run_flow(action),
        Some(Command::Agent { action }) => run_agent(action).await,
        Some(Command::Swarm { action }) => run_swarm(action).await,
        Some(Command::Triage { action }) => run_triage(action).await,
        Some(Command::Kickoff { template, path }) => {
            kickoff::run_kickoff(&template, &path)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Arch { path, format, html }) => run_arch(&path, format, html),
        Some(Command::Mcp) => {
            mcp::run_mcp_server()?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `vord arch`: analyze the component graph and render it in the requested
/// form. `--html` writes the interactive viewer *in addition to* the chosen
/// format, mirroring how `--blame-output`/`--compliance-pdf` are byproducts
/// of a scan rather than alternatives to it.
fn run_arch(
    path: &std::path::Path,
    format: ArchFormat,
    html: Option<PathBuf>,
) -> anyhow::Result<ExitCode> {
    let summary = arch::analyze(path)?;
    match format {
        ArchFormat::Text => print!("{}", arch::render_text(&summary)),
        ArchFormat::Mermaid => print!("{}", arch::render_mermaid(&summary)),
        ArchFormat::Json => println!("{}", arch::render_json(&summary)?),
    }
    if let Some(html_path) = html {
        std::fs::write(&html_path, arch::render_html(&summary)?).map_err(|e| {
            anyhow::anyhow!(
                "cannot write architecture viewer to {}: {e}",
                html_path.display()
            )
        })?;
        println!(
            "🌐 Wrote interactive architecture viewer to {}",
            html_path.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `vord agent`'s entry points. Unlike the hook, these do **not** fail open:
/// a run that could not judge, could not analyse or could not reach the model
/// exits 1, distinct from every verdict, because an agent that reports
/// success when it could not check is worse than one that reports nothing.
async fn run_agent(action: AgentAction) -> anyhow::Result<ExitCode> {
    let root = std::env::current_dir()?;
    match action {
        AgentAction::Run {
            task,
            scope,
            rule,
            max_turns,
            max_tokens,
            model,
        } => {
            let args = vord_cli::agent::AgentArgs {
                task,
                scope,
                rule,
                max_turns,
                max_tokens,
                model,
            };
            let outcome = vord_cli::agent::run(&root, args).await?;
            vord_cli::agent::report(&outcome);
            Ok(ExitCode::from(outcome.exit_code()))
        }
        AgentAction::Tui {
            task,
            scope,
            rule,
            max_turns,
            max_tokens,
            model,
        } => {
            let args = vord_cli::agent::AgentArgs {
                task,
                scope,
                rule,
                max_turns,
                max_tokens,
                model,
            };
            let outcome = tui::run(&root, args).await?;
            vord_cli::agent::report(&outcome);
            Ok(ExitCode::from(outcome.exit_code()))
        }
        AgentAction::WatchPr {
            pr,
            repo,
            window_secs,
        } => {
            let outcome = vord_cli::agent::watch_pull_request(repo, pr, window_secs).await?;
            vord_cli::agent::report_feedback(&outcome);
            Ok(ExitCode::from(outcome.exit_code()))
        }
    }
}

/// The guardrail's three entry points. `ClaudeCode` deliberately swallows
/// its own errors into a success exit inside `run_claude_code` (failing open
/// keeps a vord bug from wedging the agent loop); the other two report
/// errors normally through `main`'s handler.
async fn run_hook(action: HookAction) -> anyhow::Result<ExitCode> {
    match action {
        HookAction::ClaudeCode => vord_cli::hook::run_claude_code().await,
        HookAction::Check { file, format } => {
            let format = match format {
                Format::Text => vord_cli::hook::HookOutputFormat::Text,
                Format::Json | Format::Sarif => vord_cli::hook::HookOutputFormat::Json,
            };
            vord_cli::hook::run_check(file, format).await
        }
        HookAction::Install { command } => {
            let root = std::env::current_dir()?;
            let command = command.unwrap_or_else(|| hook_install::DEFAULT_HOOK_COMMAND.to_string());
            hook_install::install(&root, &command)?;
            Ok(ExitCode::SUCCESS)
        }
        HookAction::ResetCircuitBreaker => {
            let root = std::env::current_dir()?;
            vord_cli::hook::reset_circuit_breaker(&root)?;
            println!("vord: circuit breaker state cleared.");
            Ok(ExitCode::SUCCESS)
        }
        HookAction::Approve { token } => {
            let root = std::env::current_dir()?;
            vord_cli::hook::approve_escalation(&root, &token)?;
            println!(
                "vord: escalation token {token} approved — the agent may retry the identical write once."
            );
            Ok(ExitCode::SUCCESS)
        }
        HookAction::ResetLoopGuard => {
            let root = std::env::current_dir()?;
            vord_cli::hook::reset_loop_guard(&root)?;
            println!("vord: loop alarm state cleared.");
            Ok(ExitCode::SUCCESS)
        }
        HookAction::Audit { limit, format } => {
            let root = std::env::current_dir()?;
            let entries = vord_cli::hook::read_audit_log(&root, Some(limit));
            match format {
                Format::Text => print!("{}", vord_cli::hook::render_audit_text(&entries)),
                Format::Json | Format::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&entries)?)
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `vord swarm`'s entry points (roadmap B). Every failure here is a config
/// or `git` error, not a policy verdict, so unlike `vord hook`/`vord agent`
/// there is no fail-open story to preserve — errors propagate normally
/// through `main`'s handler. `Run` is the one action that also carries an
/// agent-run exit code, same convention as `run_agent`'s `Run`/`Tui`.
async fn run_swarm(action: SwarmAction) -> anyhow::Result<ExitCode> {
    let root = std::env::current_dir()?;
    match action {
        SwarmAction::Roles => {
            print_roles(&vord_cli::swarm::list_roles(&root)?);
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::WorktreeCreate { role, base } => {
            let plan = vord_cli::swarm::worktree_create(&root, &role, &base)?;
            println!(
                "vord swarm: created worktree for `{role}` at {} (branch {})",
                plan.path.display(),
                plan.branch
            );
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::WorktreeRemove { role, force } => {
            let plan = vord_cli::swarm::worktree_remove(&root, &role, force)?;
            println!(
                "vord swarm: removed worktree for `{role}` at {}",
                plan.path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::WorktreeList => {
            let worktrees = vord_cli::swarm::worktree_list(&root)?;
            for worktree in worktrees {
                println!(
                    "{} ({})",
                    worktree.path,
                    worktree.branch.as_deref().unwrap_or("detached")
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::HandoffSend { from, to, summary } => {
            let handoff = vord_cli::swarm::handoff_send(&root, &from, &to, &summary)?;
            println!("vord swarm: queued handoff {} ({from} -> {to})", handoff.id);
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::HandoffDeliver => {
            let delivered = vord_cli::swarm::handoff_deliver(&root)?;
            println!("vord swarm: delivered {} handoff(s)", delivered.len());
            for handoff in delivered {
                println!(
                    "  {} -> {} ({})",
                    handoff.from_role, handoff.to_role, handoff.id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::HandoffInbox { role } => {
            let waiting = vord_cli::swarm::handoff_inbox(&root, &role)?;
            for handoff in waiting {
                println!(
                    "{} from {}: {}",
                    handoff.id, handoff.from_role, handoff.summary
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::HandoffAck { role, id } => {
            vord_cli::swarm::handoff_ack(&root, &role, &id)?;
            println!("vord swarm: acknowledged {id} for `{role}`");
            Ok(ExitCode::SUCCESS)
        }
        SwarmAction::Run { task } => run_topology(&root, &task).await,
        SwarmAction::Tui => {
            vord_cli::swarm::run_swarm_tui(&root)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn run_triage(action: TriageAction) -> anyhow::Result<ExitCode> {
    let root = std::env::current_dir()?;
    match action {
        TriageAction::Advance {
            issue,
            repro_command,
        } => {
            let report = vord_cli::triage::advance(&root, issue, repro_command.as_deref()).await?;
            println!("{}", report.message);
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `vord swarm roles`: one role's resolved worktree plan and scope
/// narrowing per line, or a pointer to configure one if there are none.
fn print_roles(roles: &[vord_cli::swarm::RoleReport]) {
    if roles.is_empty() {
        println!("vord swarm: no roles configured — add [[swarm.role]] entries to vord.toml.");
        return;
    }
    for role in roles {
        println!(
            "{} — worktree {} (branch {}), +{} protected path(s), +{} blocking rule(s), +{} escalate rule(s)",
            role.name,
            role.plan.path.display(),
            role.plan.branch,
            role.extra_protected_paths,
            role.extra_blocking_rules,
            role.extra_escalate_rules,
        );
    }
}

/// `vord swarm run`: drives the configured topology end to end and exits
/// with the exit code of whichever role stopped the pipeline (or `0` if
/// every role completed) — the same distinct-exit-code convention `vord
/// agent run` already established.
async fn run_topology(root: &Path, task: &str) -> anyhow::Result<ExitCode> {
    let results = vord_cli::swarm::topology_run(root, task).await?;
    let mut exit_code = 0u8;
    for result in &results {
        println!(
            "vord swarm: [{}] {} (after {} turns)",
            result.role,
            result.outcome.describe(),
            result.outcome.turns()
        );
        if result.outcome.exit_code() != 0 {
            exit_code = result.outcome.exit_code();
        }
    }
    Ok(ExitCode::from(exit_code))
}

async fn run_fix(path: PathBuf, issue: String, model: Option<String>) -> anyhow::Result<ExitCode> {
    println!(
        "🤖 Requesting AI remediation for issue '{issue}' in {}...",
        path.display()
    );

    let (path, verdict) = vord_cli::remediate_issue(&path, &issue, model).await?;

    match verdict {
        vord_remediation::RemediationVerdict::Accepted { proposal } => {
            println!(
                "\n✅ Verified fix applied to {} (issue gone, no regressions):\n",
                path.display()
            );
            println!("{}", proposal.replacement_snippet);
            println!("\nExplanation: {}", proposal.explanation);
            Ok(ExitCode::SUCCESS)
        }
        vord_remediation::RemediationVerdict::Rejected { reason } => {
            eprintln!("❌ Remediation Agent could not produce a verified fix: {reason}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn parse_fail_on_threshold(fail_on: Option<String>) -> anyhow::Result<Option<Severity>> {
    fail_on
        .map(|raw| {
            Severity::parse(&raw).ok_or_else(|| {
                anyhow::anyhow!("invalid severity {raw:?} (info|minor|major|critical|blocker)")
            })
        })
        .transpose()
}

/// `vord.toml`'s `[analysis] sources`/`inclusions`/`exclusions`/`profile`/
/// `[project] key`, or all empty when there's no project config (a bare
/// directory/file scan).
#[derive(Default)]
struct ProjectScope {
    source_dirs: Vec<String>,
    inclusions: Vec<String>,
    exclusions: Vec<String>,
    project_key: Option<String>,
    duplication: vord_infra_fs::DuplicationSettings,
    architecture: vord_infra_fs::ArchitectureSettings,
    gate: vord_infra_fs::GateSettings,
    config_profile: Option<String>,
    vite_react: vord_infra_fs::ViteReactSettings,
    secrets: vord_infra_fs::SecretsSettings,
    flows: Vec<vord_infra_fs::FlowConfig>,
    rules_custom: Vec<vord_infra_fs::CustomRuleConfig>,
}

fn load_project_scope(path: &std::path::Path) -> ProjectScope {
    vord_infra_fs::VordConfig::load_from_dir(path)
        .map(|config| {
            if let Some(key) = &config.project.key {
                eprintln!("📋 Loaded project config ({key})");
            }
            ProjectScope {
                source_dirs: config.analysis.sources.unwrap_or_default(),
                inclusions: config.analysis.inclusions.unwrap_or_default(),
                exclusions: config.analysis.exclusions.unwrap_or_default(),
                project_key: config.project.key,
                duplication: config.duplication,
                architecture: config.architecture,
                gate: config.gate,
                config_profile: config.analysis.profile,
                vite_react: config.vite_react,
                secrets: config.secrets,
                flows: config.flows,
                rules_custom: config.rules.custom,
            }
        })
        .unwrap_or_default()
}

/// Resolved scan identity/target: `--project`/`--branch`/`--pr`/
/// `--commit-sha`/`--github-repo`, each an explicit flag if given, else the
/// CI-auto-detected value, else (for `project` only) a directory-name
/// fallback. Threaded through both ALM status reporting and the rendered
/// output's `context` so a downstream consumer sees the same identity the
/// scan itself used.
struct ResolvedContext {
    project: Option<String>,
    branch: Option<String>,
    pr: Option<u32>,
    commit_sha: Option<String>,
    github_repo: Option<String>,
}

impl ResolvedContext {
    fn to_dto(&self) -> output::ScanContextDto {
        output::ScanContextDto {
            project: self.project.clone(),
            branch: self.branch.clone(),
            pull_request: self.pr,
        }
    }
}

/// Reads real CI environment variables (`GITHUB_ACTIONS`/`GITLAB_CI`/...
/// and friends) into a [`ci_detect::CiContext`] — the one place `main`
/// touches `std::env` for CI detection; [`ci_detect::detect_ci_context`]
/// itself is pure and injected with this closure so it stays unit-testable.
/// Also covers the one CI signal that needs a file read rather than an env
/// var: GitHub Actions' `GITHUB_EVENT_PATH` payload, consulted only when
/// `GITHUB_REF` didn't already yield a PR number.
fn resolve_ci_context() -> ci_detect::CiContext {
    let env_lookup = |key: &str| std::env::var(key).ok();
    let mut ctx = ci_detect::detect_ci_context(&env_lookup);
    if ctx.pr.is_none()
        && ctx.provider == Some(ci_detect::CiProvider::GithubActions)
        && let Ok(event_path) = std::env::var("GITHUB_EVENT_PATH")
        && let Ok(raw) = std::fs::read_to_string(event_path)
    {
        ctx.pr = ci_detect::parse_pr_number_from_github_event(&raw);
    }
    ctx
}

/// Combines explicit `--project`/`--branch`/`--pr`/`--commit-sha`/
/// `--github-repo` flags with CI auto-detection (explicit always wins) and
/// `vord.toml`'s `[project] key` / the scan path's directory name as the
/// last-resort project fallback.
fn resolve_context(
    args: &ScanArgs,
    config_project_key: Option<String>,
    ci: &ci_detect::CiContext,
) -> ResolvedContext {
    let project = args
        .scope
        .project
        .clone()
        .or(config_project_key)
        .or_else(|| {
            args.path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        });
    ResolvedContext {
        project,
        branch: args.scope.branch.clone().or_else(|| ci.branch.clone()),
        pr: args.github.pr.or(ci.pr),
        commit_sha: args
            .github
            .commit_sha
            .clone()
            .or_else(|| ci.commit_sha.clone()),
        github_repo: args
            .github
            .github_repo
            .clone()
            .or_else(|| ci.github_repo.clone()),
    }
}

/// Builds the GitHub status reporter from explicit `--github-token`/
/// `--github-repo` (falling back to `context`'s CI-resolved repo) or the
/// environment (`GitHubStatusReporter::from_env`) — shared by the
/// single-project and `--monorepo` reporting paths so there's exactly one
/// place that decides how a reporter gets built.
fn github_reporter(
    args: &ScanArgs,
    context: &ResolvedContext,
) -> Option<vord_infra_github::GitHubStatusReporter> {
    match (&args.github.github_token, &context.github_repo) {
        (Some(token), Some(repo)) => {
            let (owner, name) = repo.split_once('/').unwrap_or(("local", repo));
            Some(vord_infra_github::GitHubStatusReporter::new(
                token.clone(),
                owner,
                name,
            ))
        }
        _ => vord_infra_github::GitHubStatusReporter::from_env(),
    }
}

fn parse_coverage_format(
    raw: Option<String>,
) -> anyhow::Result<Option<vord_infra_fs::CoverageFormat>> {
    raw.map(|raw| match raw.to_ascii_lowercase().as_str() {
        "lcov" => Ok(vord_infra_fs::CoverageFormat::Lcov),
        "cobertura" => Ok(vord_infra_fs::CoverageFormat::Cobertura),
        "jacoco" => Ok(vord_infra_fs::CoverageFormat::Jacoco),
        "llvm-cov" | "llvmcov" => Ok(vord_infra_fs::CoverageFormat::LlvmCov),
        "istanbul" => Ok(vord_infra_fs::CoverageFormat::Istanbul),
        other => Err(anyhow::anyhow!(
            "unknown --coverage-format {other:?} (lcov|cobertura|jacoco|llvm-cov|istanbul)"
        )),
    })
    .transpose()
}

fn read_report_file(path: &std::path::Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))
}

/// Merges every coverage report format the CLI accepts (LCOV, Cobertura,
/// JaCoCo, llvm-cov, Istanbul, or an auto-detected `--coverage-report`)
/// into one running total plus per-file detail. `_report` parse functions
/// carry the per-file/per-line detail needed for coverage-on-new-code
/// alongside the flat totals; the detail is merged into `detail` while the
/// totals feed the plain `CoverageSummary` the rest of the pipeline
/// already understands (`coverage`/`branch_coverage` measures, gate).
#[derive(Default)]
struct CoverageAccumulator {
    summary: Option<vord_rules_engine::CoverageSummary>,
    detail: Option<vord_rules_engine::CoverageReport>,
}

impl CoverageAccumulator {
    fn merge(&mut self, parsed: vord_rules_engine::CoverageReport) -> anyhow::Result<()> {
        let summary = parsed.summary()?;
        match &mut self.summary {
            Some(acc) => {
                acc.add(summary.covered_lines(), summary.coverable_lines())?;
                acc.add_branches(summary.covered_branches(), summary.coverable_branches())?;
            }
            None => self.summary = Some(summary),
        }
        match &mut self.detail {
            Some(acc) => acc.merge(parsed),
            None => self.detail = Some(parsed),
        }
        Ok(())
    }

    fn apply_to(self, report: &mut vord_rules_engine::AnalysisReport) {
        if let Some(summary) = self.summary {
            report.set_coverage(summary);
        }
        if let Some(detail) = self.detail {
            report.set_coverage_report(detail);
        }
    }
}

fn ingest_coverage(args: &ScanArgs) -> anyhow::Result<CoverageAccumulator> {
    let mut acc = CoverageAccumulator::default();
    if let Some(path) = &args.coverage.coverage {
        acc.merge(vord_infra_fs::parse_lcov_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.cobertura {
        acc.merge(vord_infra_fs::parse_cobertura_report(&read_report_file(
            path,
        )?)?)?;
    }
    if let Some(path) = &args.coverage.jacoco {
        acc.merge(vord_infra_fs::parse_jacoco_report(&read_report_file(
            path,
        )?)?)?;
    }
    if let Some(path) = &args.coverage.llvm_cov {
        acc.merge(vord_infra_fs::parse_llvm_cov_report(&read_report_file(
            path,
        )?)?)?;
    }
    if let Some(path) = &args.coverage.istanbul {
        acc.merge(vord_infra_fs::parse_istanbul_report(&read_report_file(
            path,
        )?)?)?;
    }
    if let Some(path) = &args.coverage.coverage_report {
        let raw = read_report_file(path)?;
        let format = parse_coverage_format(args.coverage.coverage_format.clone())?;
        acc.merge(vord_infra_fs::parse_coverage_report(&raw, format)?)?;
    }
    Ok(acc)
}

/// Coverage-on-new-code: restricts the ingested coverage detail to the
/// lines a supplied unified diff marks as added/modified. Basic by
/// design — no git invocation here, the caller supplies the diff (e.g.
/// `git diff main...HEAD --unified=0 > diff.txt`).
fn coverage_new_code_measure(
    coverage_diff: Option<PathBuf>,
    report: &vord_rules_engine::AnalysisReport,
) -> anyhow::Result<Option<f64>> {
    Ok(coverage_diff
        .map(|path| read_report_file(&path))
        .transpose()?
        .map(|raw| vord_infra_fs::changed_lines_from_unified_diff(&raw))
        .and_then(|changed| report.coverage_on_new_code(&changed)))
}

/// `--sarif`: merges another analyzer's findings into this scan's report.
/// One importer, every tool that speaks SARIF — the coverage of ruff,
/// ESLint, clippy, gosec, bandit, semgrep and CodeQL without vord
/// implementing any of their rules.
///
/// Paths in the report are re-based onto the scan root so imported issues
/// key by the same relative path vord's own issues do (`Issue::file()`),
/// which is what lets the two sets coexist in one report, one gate and one
/// New Code baseline.
fn ingest_sarif(
    args: &ScanArgs,
    report: &mut vord_rules_engine::AnalysisReport,
) -> anyhow::Result<()> {
    if args.reports.sarif.is_empty() {
        return Ok(());
    }

    // Report URIs are relative to the project root, which for a single-file
    // scan is the file's directory rather than the file itself.
    let root = if args.path.is_dir() {
        args.path.clone()
    } else {
        args.path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf()
    };

    let (mut imported, mut skipped) = (0usize, 0usize);
    let mut tools: Vec<String> = Vec::new();
    for path in &args.reports.sarif {
        let raw = read_report_file(path)?;
        let import = vord_infra_fs::parse_sarif_relative_to(&raw, &root)
            .map_err(|e| anyhow::anyhow!("cannot import SARIF from {}: {e}", path.display()))?;
        imported += import.issues.len();
        skipped += import.skipped;
        for tool in import.tools {
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
        report.add_external_issues(import.issues);
    }

    let tools = if tools.is_empty() {
        "unknown tool".to_string()
    } else {
        tools.join(", ")
    };
    eprintln!(
        "📥 Imported {imported} issue(s) from {} SARIF report(s) [{tools}]{}",
        args.reports.sarif.len(),
        if skipped > 0 {
            format!(" — {skipped} result(s) skipped (passing, suppressed or location-less)")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn load_test_report(
    junit: Option<PathBuf>,
) -> anyhow::Result<Option<vord_rules_engine::TestReportSummary>> {
    junit
        .map(|path| {
            vord_infra_fs::parse_junit(&read_report_file(&path)?).map_err(anyhow::Error::from)
        })
        .transpose()
}

fn load_mutation_report(
    mutation_report: Option<PathBuf>,
) -> anyhow::Result<Option<vord_rules_engine::MutationSummary>> {
    mutation_report
        .map(|path| {
            vord_infra_fs::parse_mutation_report(&read_report_file(&path)?)
                .map_err(anyhow::Error::from)
        })
        .transpose()
}

/// New Code (previous-analysis mode): classifies against the stored
/// baseline, then advances the baseline to this analysis. Line hashes are
/// read from the real source tree so tracking survives a message that
/// drifted (e.g. a complexity count changing) without the underlying
/// issue moving or disappearing.
fn classify_new_code(
    path: &std::path::Path,
    no_baseline: bool,
    report: &vord_rules_engine::AnalysisReport,
) -> Option<NewCodeAnalysis> {
    let baseline_store = (!no_baseline && path.is_dir())
        .then(|| BaselineStore::new(path.join(".vord-baseline.json")))?;
    let line_hashes = vord_cli::FileLineHashes::new(path);
    let hash_fn = |file: &str, line: u32| line_hashes.hash(file, line);
    let new_code = baseline_store
        .load()
        .map(|baseline| NewCodeAnalysis::classify_with_source(report, &baseline, hash_fn));
    if let Err(e) = baseline_store.save(&Baseline::from_report_with_source(report, hash_fn)) {
        eprintln!("warning: could not persist New Code baseline: {e}");
    }
    new_code
}

/// Posts a PR review comment summarizing new issues, when `pr` (explicit
/// `--pr`, or CI-auto-detected — see [`resolve_context`]) is known. Used to
/// hand-derive the PR number from `GITHUB_REF`/`GITHUB_EVENT_PATH` inline
/// here; that detection now lives in `ci_detect` so it's covered by unit
/// tests instead of only exercised by a real GitHub Actions run.
async fn report_pull_request_review(
    reporter: &vord_infra_github::GitHubStatusReporter,
    pr: Option<u32>,
    new_code: Option<&NewCodeAnalysis>,
    desc: &str,
) {
    use vord_rules_engine::AlmPullRequestReporter;
    let Some(pr_num) = pr else { return };
    let Ok(pr_number) = vord_rules_engine::PullRequestNumber::new(pr_num) else {
        return;
    };

    let new_issues = new_code.map(|nc| nc.new_issues()).unwrap_or(&[]);
    if let Err(e) = reporter
        .report_pull_request_review(pr_number, new_issues, desc)
        .await
    {
        eprintln!("warning: could not report pull request review to GitHub: {e}");
    }
}

/// Reports the scan's commit status (and, on a PR analysis, a review) to
/// GitHub when a commit SHA and GitHub credentials/env are available. The
/// commit SHA, PR number and repo slug all come from `context`
/// ([`resolve_context`]) — explicit `--commit-sha`/`--pr`/`--github-repo`
/// flags win, otherwise CI auto-detection fills them in.
async fn report_to_github(
    args: &ScanArgs,
    context: &ResolvedContext,
    report: &vord_rules_engine::AnalysisReport,
    gate: &vord_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
) {
    use vord_rules_engine::{AlmStatusReporter, CommitStatus, CommitStatusState};

    let Some(sha_str) = &context.commit_sha else {
        return;
    };
    let Ok(sha) = vord_rules_engine::CommitSha::new(sha_str) else {
        return;
    };

    let Some(reporter) = github_reporter(args, context) else {
        return;
    };

    let state = if gate.status() == vord_rules_engine::GateStatus::Passed {
        CommitStatusState::Success
    } else {
        CommitStatusState::Failure
    };
    let gate_label = match gate.status() {
        vord_rules_engine::GateStatus::Passed => "passed",
        vord_rules_engine::GateStatus::Failed => "failed",
    };
    let desc = format!("Gate {gate_label}: {} issues found", report.issues().len());
    let status = CommitStatus::new(state, desc.clone());
    if let Err(e) = reporter.report_commit_status(&sha, &status).await {
        eprintln!("warning: could not report commit status to GitHub: {e}");
    }

    report_pull_request_review(&reporter, context.pr, new_code, &desc).await;
}

fn render_output(
    args: &ScanArgs,
    report: &vord_rules_engine::AnalysisReport,
    gate: &vord_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
    test_report: Option<&vord_rules_engine::TestReportSummary>,
    coverage_new_code: Option<f64>,
    context: &output::ScanContextDto,
) -> anyhow::Result<()> {
    match args.output.format {
        Format::Text => {
            print!(
                "{}",
                output::render_text(
                    report,
                    gate,
                    new_code,
                    test_report,
                    coverage_new_code,
                    context,
                    args.show_resolved,
                )
            )
        }
        Format::Json => {
            println!(
                "{}",
                output::render_json(
                    report,
                    gate,
                    new_code,
                    test_report,
                    coverage_new_code,
                    context.clone(),
                    args.show_resolved,
                )?
            )
        }
        Format::Sarif => {
            println!("{}", output::render_sarif(report)?);
        }
    }
    if args.output.agent_prompt {
        println!(
            "\n{}",
            output::render_agent_prompt(report, gate, &args.path.display().to_string())
        );
    }
    Ok(())
}

/// `--blame-output`: captures per-line SCM blame for every file the scan
/// found an issue in and writes it as JSON to the given path. Best-effort —
/// a scan target that isn't inside a Git repository (or has no `git`
/// binary available) warns and is otherwise a no-op rather than failing the
/// whole scan, matching the cache/baseline persistence warnings above.
///
/// `Issue::file()` is relative to the *scan root* (`args.path`), but `git
/// blame` needs a path relative to the *Git root* — which can be a parent
/// directory of the scan root (e.g. `vord scan services/api` inside a
/// larger repo). This re-bases each issue's file onto the Git root before
/// blaming it, then keys the output back by the scan-relative path so it
/// still lines up with `Issue::file()` for any consumer cross-referencing
/// the two.
fn write_blame_output(args: &ScanArgs, report: &vord_rules_engine::AnalysisReport) {
    let Some(output_path) = &args.output.blame_output else {
        return;
    };
    let Some(git_root) = vord_cli::find_git_root(&args.path) else {
        eprintln!(
            "warning: --blame-output given but {} is not inside a Git repository — skipping blame capture",
            args.path.display()
        );
        return;
    };

    let scan_root = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());
    let prefix = scan_root
        .strip_prefix(&git_root)
        .unwrap_or(std::path::Path::new(""));

    let mut report_files: Vec<String> = report
        .issues()
        .iter()
        .map(|issue| issue.file().to_string())
        .collect();
    report_files.sort();
    report_files.dedup();

    // `blame::blame_files` operates purely on paths relative to the Git
    // root; re-key its result back to the scan-relative paths the report
    // itself uses, via this git-relative -> scan-relative lookup.
    let git_relative_to_scan_relative: std::collections::HashMap<String, String> = report_files
        .iter()
        .map(|file| {
            (
                prefix.join(file).to_string_lossy().replace('\\', "/"),
                file.clone(),
            )
        })
        .collect();
    let git_relative_files: Vec<String> = git_relative_to_scan_relative.keys().cloned().collect();

    let blame: std::collections::BTreeMap<String, Vec<blame::BlameLine>> =
        blame::blame_files(&git_root, &git_relative_files)
            .into_iter()
            .filter_map(|(git_relative, lines)| {
                git_relative_to_scan_relative
                    .get(&git_relative)
                    .cloned()
                    .map(|scan_relative| (scan_relative, lines))
            })
            .collect();

    match serde_json::to_string_pretty(&blame) {
        Ok(json) => match std::fs::write(output_path, json) {
            Ok(()) => println!(
                "📝 Wrote SCM blame for {} file(s) to {}",
                blame.len(),
                output_path.display()
            ),
            Err(e) => eprintln!(
                "warning: could not write blame output to {}: {e}",
                output_path.display()
            ),
        },
        Err(e) => eprintln!("warning: could not serialize blame output: {e}"),
    }
}

/// `--compliance-pdf`/`--compliance-csv`: OWASP Top 10 / CWE / PCI DSS
/// evidence reports (`vord_infra_pdf::ComplianceReportGenerator`) for
/// whichever paths were given — either, neither or both independently, the
/// same "only do what was asked for" shape `--blame-output` uses. Best-effort:
/// a write failure warns rather than failing the whole scan, since the
/// report is a byproduct of the analysis, not the analysis itself.
fn write_compliance_reports(args: &ScanArgs, report: &vord_rules_engine::AnalysisReport) {
    if let Some(output_path) = &args.output.compliance_pdf {
        match vord_infra_pdf::ComplianceReportGenerator::generate_owasp_compliance_pdf_binary(
            report,
        ) {
            Ok(pdf) => match std::fs::write(output_path, pdf) {
                Ok(()) => println!("📝 Wrote compliance report to {}", output_path.display()),
                Err(e) => eprintln!(
                    "warning: could not write compliance PDF to {}: {e}",
                    output_path.display()
                ),
            },
            Err(e) => eprintln!("warning: could not generate compliance PDF: {e}"),
        }
    }
    if let Some(output_path) = &args.output.compliance_csv {
        match vord_infra_pdf::ComplianceReportGenerator::generate_csv(report) {
            Ok(csv) => match std::fs::write(output_path, csv) {
                Ok(()) => println!("📝 Wrote compliance report to {}", output_path.display()),
                Err(e) => eprintln!(
                    "warning: could not write compliance CSV to {}: {e}",
                    output_path.display()
                ),
            },
            Err(e) => eprintln!("warning: could not generate compliance CSV: {e}"),
        }
    }
}

/// Writes mutation-gap findings (rules starting with `mutation:`) to
/// `.vord-mutation-gaps.json` — a separate, explorable file so AI agents
/// don't burn context on 9,000+ informational hints. The main output only
/// shows a count; the full per-file, per-rule breakdown lives here.
fn write_mutation_gaps(args: &ScanArgs, report: &vord_rules_engine::AnalysisReport) {
    let gaps: Vec<&vord_rules_engine::Issue> = report
        .issues()
        .iter()
        .filter(|i| vord_cli::output::is_mutation_rule(i.rule().as_str()))
        .collect();
    if gaps.is_empty() {
        return;
    }

    use std::collections::BTreeMap;
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_file: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for gap in &gaps {
        *by_rule.entry(gap.rule().to_string()).or_default() += 1;
        by_file
            .entry(gap.file().to_string())
            .or_default()
            .push(serde_json::json!({
                "rule": gap.rule().to_string(),
                "line": gap.span().start_line,
                "message": gap.message(),
            }));
    }

    let output = serde_json::json!({
        "total_gaps": gaps.len(),
        "by_rule": by_rule,
        "by_file": by_file,
    });

    let output_path = if args.path.is_dir() {
        args.path.join(".vord-mutation-gaps.json")
    } else {
        args.path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(".vord-mutation-gaps.json")
    };
    match serde_json::to_string_pretty(&output) {
        Ok(json) => match std::fs::write(&output_path, json) {
            Ok(()) => eprintln!(
                "🧬 Wrote {} mutation-gap site(s) to {}",
                gaps.len(),
                output_path.display()
            ),
            Err(e) => eprintln!(
                "warning: could not write mutation gaps to {}: {e}",
                output_path.display()
            ),
        },
        Err(e) => eprintln!("warning: could not serialize mutation gaps: {e}"),
    }
}

fn exit_code(
    threshold: Option<Severity>,
    report: &vord_rules_engine::AnalysisReport,
    enforce_gate: bool,
    gate: &vord_rules_engine::GateEvaluation,
    min_health_score: Option<u32>,
) -> ExitCode {
    let breached = threshold
        .zip(report.max_severity())
        .is_some_and(|(threshold, max)| max >= threshold);
    let gate_failed = enforce_gate && gate.status() == vord_rules_engine::GateStatus::Failed;
    let health_below =
        enforce_gate && min_health_score.is_some_and(|min| report.health_score() < min);
    if breached || gate_failed || health_below {
        if health_below {
            let min = min_health_score.unwrap_or(0);
            eprintln!(
                "❌ Health score {} is below minimum {} — gate failed",
                report.health_score(),
                min
            );
        }
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_scan(args: ScanArgs) -> anyhow::Result<ExitCode> {
    if args.scope.monorepo {
        return monorepo_scan::run(&args).await;
    }

    let threshold = parse_fail_on_threshold(args.fail_on.clone())?;
    let ProjectScope {
        source_dirs,
        inclusions,
        exclusions,
        project_key: config_project_key,
        duplication,
        architecture,
        gate: gate_config,
        config_profile: _config_profile,
        vite_react,
        secrets,
        flows,
        rules_custom,
    } = load_project_scope(&args.path);
    // `--profile` is the only trigger in this increment: `vord.toml`'s own
    // `[analysis] profile` stays parsed-but-unread (see `VordConfig`'s own
    // doc note), same as before this flag existed, so omitting `--profile`
    // is byte-for-byte the "vord way"/`default_quality_gate` behavior every
    // scan used prior to this — wiring the config-file default is deferred,
    // not silently smuggled in through a fixture that happens to set it.
    let profile_name = args.profile.clone();
    let profile = match &profile_name {
        Some(name) => Some(vord_rules_engine::profile_by_name(name).ok_or_else(|| {
            anyhow::anyhow!(
                "unrecognized --profile {name:?} (known profiles: \"vord way\", \"vite-react-frontend-starter\")"
            )
        })?),
        None => None,
    };
    let min_health_score = args.min_health_score.or(gate_config.min_health_score);
    let ci = resolve_ci_context();
    let context = resolve_context(&args, config_project_key, &ci);

    let cache = (!args.no_cache && args.path.is_dir())
        .then(|| std::sync::Arc::new(FileAnalysisCache::open(args.path.join(".vord-cache.json"))));
    let mut report = vord_cli::scan_with_profile(
        &args.path,
        cache.clone(),
        &source_dirs,
        &inclusions,
        &exclusions,
        &vord_cli::ProjectSettings {
            duplication: &duplication,
            architecture: &architecture,
            vite_react: &vite_react,
            secrets: &secrets,
            rules_custom: &rules_custom,
        },
        profile,
    )
    .await?;

    // Before the gate and the New Code baseline: imported findings are
    // ordinary issues from here on, so both must see them.
    ingest_sarif(&args, &mut report)?;
    ingest_coverage(&args)?.apply_to(&mut report);
    let coverage_new_code =
        coverage_new_code_measure(args.coverage.coverage_diff.clone(), &report)?;
    crap::apply(&mut report);
    flow::apply_auto_detected(&mut report, &args.path);
    flow::apply_registered(&mut report, &args.path, &flows);

    let test_report = load_test_report(args.reports.junit.clone())?;
    if let Some(summary) = &test_report {
        report.set_test_report(summary.clone());
    }
    if let Some(mutation) = load_mutation_report(args.reports.mutation_report.clone())? {
        report.set_mutation(mutation);
    }
    if let Some(cache) = &cache
        && let Err(e) = cache.persist()
    {
        eprintln!("warning: could not persist analysis cache: {e}");
    }

    let new_code = classify_new_code(&args.path, args.no_baseline, &report);

    // Gate conditions may target overall (`blocker_issues`), new-issue
    // (`new_blocker_issues`) or coverage-on-new-code (`coverage_new_code`)
    // measures.
    let gate = vord_cli::quality_gate_for_profile(profile_name.as_deref()).evaluate(|key| {
        if key.as_str() == "coverage_new_code" {
            return coverage_new_code;
        }
        new_code
            .as_ref()
            .and_then(|nc| nc.measure(key))
            .or_else(|| report.measure(key))
    });

    write_mutation_gaps(&args, &report);
    report_to_github(&args, &context, &report, &gate, new_code.as_ref()).await;
    write_blame_output(&args, &report);
    write_compliance_reports(&args, &report);
    render_output(
        &args,
        &report,
        &gate,
        new_code.as_ref(),
        test_report.as_ref(),
        coverage_new_code,
        &context.to_dto(),
    )?;

    Ok(exit_code(
        threshold,
        &report,
        args.enforce_gate,
        &gate,
        min_health_score,
    ))
}
// vord pre-commit hook verified
