//! Filesystem source loader: walks a directory (gitignore-aware) and
//! translates readable files in supported languages into validated
//! [`SourceFile`]s. Unsupported and non-UTF-8 files are skipped.

mod agent_workspace;
mod baseline;
mod cache;
mod cobertura;
mod config;
mod coverage;
mod dependency_graph;
mod diff;
mod gherkin;
mod handoff;
mod istanbul;
mod jacoco;
mod junit;
mod lcov;
mod llvm_cov;
mod monorepo;
mod mutation;
mod rust_crates;
mod sarif;
mod swarm_worktree;
mod tsconfig;
mod worktree;

pub use agent_workspace::RepoWorkspace;
pub use baseline::BaselineStore;
pub use cache::FileAnalysisCache;
pub use cobertura::{CoberturaError, parse_cobertura, parse_cobertura_report};
pub use config::{
    AgentSettings, ArchitectureSettings, CustomRuleConfig, DependencyEdgeConfig,
    DuplicationSettings, FlowConfig, FlowStepConfig, GateSettings, LayerConfig, RoleProtectedPath,
    RoleSettings, RulesConfig, SecretsSettings, SwarmSettings, ViteReactSettings, VordConfig,
};
pub use coverage::{
    CoverageFormat, CoverageParseError, detect_coverage_format, parse_coverage_report,
};
pub use dependency_graph::{ParsedImportGraph, build as build_dependency_graph};
pub use diff::changed_lines_from_unified_diff;
pub use gherkin::{
    COVERS_TAG, CoversClaim, GherkinCoverageError, GherkinCoverageIndex, extract_covers_patterns,
    scan_covers_claims,
};
pub use handoff::{HandoffIoError, ack, deliver, inbox, send as send_handoff};
pub use istanbul::{IstanbulError, parse_istanbul, parse_istanbul_report};
pub use jacoco::{JacocoError, parse_jacoco, parse_jacoco_report};
pub use junit::{JunitError, parse_junit};
pub use lcov::{LcovError, parse_lcov, parse_lcov_report};
pub use llvm_cov::{LlvmCovError, parse_llvm_cov, parse_llvm_cov_report};
pub use monorepo::discover_projects;
pub use mutation::{MutationParseError, parse_mutation_report};
pub use rust_crates::discover_rust_crates;
pub use sarif::{SarifError, SarifImport, parse_sarif, parse_sarif_relative_to};
pub use swarm_worktree::{
    SwarmWorktreeError, WorktreeStatus, create_worktree, list_worktrees, remove_worktree,
};
pub use tsconfig::discover_ts_path_aliases;
pub use worktree::WorktreeSandbox;

use std::io::ErrorKind;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use vord_ast::{LanguageIdentifier, SourceFile};

#[derive(Debug, thiserror::Error)]
pub enum SourceLoadError {
    #[error("failed to walk {0}")]
    Walk(String),
    #[error("invalid exclusion pattern {0:?}: {1}")]
    InvalidExclusion(String, globset::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn collect_sources(root: &Path) -> Result<Vec<SourceFile>, SourceLoadError> {
    collect_sources_excluding(root, &[])
}

/// Same as [`collect_sources`], but skips any file whose path relative to
/// `root` matches one of the given glob patterns — `vord.toml`'s
/// `[analysis] exclusions`.
pub fn collect_sources_excluding(
    root: &Path,
    exclusions: &[String],
) -> Result<Vec<SourceFile>, SourceLoadError> {
    collect_sources_scoped(root, &[], &[], exclusions)
}

/// Same as [`collect_sources_excluding`], but when `source_dirs` is
/// non-empty only walks those directories (relative to `root`) instead of
/// the whole tree — `vord.toml`'s `[analysis] sources`. An empty
/// `source_dirs` walks all of `root`, same as before.
///
/// `inclusions` is `vord.toml`'s `[analysis] inclusions`: when non-empty, a
/// file must match at least one of these globs (relative to `root`) to be
/// kept, same convention as `sonar.inclusions` in `sonar-project.properties`
/// — it narrows the walk, `exclusions` further narrows what's left. An
/// empty `inclusions` keeps every file, same as before this parameter
/// existed.
pub fn collect_sources_scoped(
    root: &Path,
    source_dirs: &[String],
    inclusions: &[String],
    exclusions: &[String],
) -> Result<Vec<SourceFile>, SourceLoadError> {
    let includes = (!inclusions.is_empty())
        .then(|| build_globset(inclusions))
        .transpose()?;
    let excludes = build_globset(exclusions)?;
    let roots: Vec<std::path::PathBuf> = if source_dirs.is_empty() {
        vec![root.to_path_buf()]
    } else {
        source_dirs.iter().map(|dir| root.join(dir)).collect()
    };

    let mut sources = Vec::new();
    for walk_root in &roots {
        for entry in WalkBuilder::new(walk_root).build() {
            let entry = entry.map_err(|e| SourceLoadError::Walk(e.to_string()))?;
            if let Some(source) = load_source_entry(&entry, root, includes.as_ref(), &excludes)? {
                sources.push(source);
            }
        }
    }
    sources.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(sources)
}

/// Loads one walk entry into a [`SourceFile`], or `None` if it's not a
/// regular file, has an unsupported extension, fails an inclusion/exclusion
/// glob, or isn't valid UTF-8 — every case `collect_sources_scoped`'s loop
/// body used to skip inline via `continue`.
fn load_source_entry(
    entry: &ignore::DirEntry,
    root: &Path,
    includes: Option<&GlobSet>,
    excludes: &GlobSet,
) -> Result<Option<SourceFile>, SourceLoadError> {
    if !entry.file_type().is_some_and(|t| t.is_file()) {
        return Ok(None);
    }
    let path = entry.path();
    let Some(language) = path
        .extension()
        .and_then(|e| e.to_str())
        .and_then(LanguageIdentifier::from_extension)
    else {
        return Ok(None);
    };
    let relative = path.strip_prefix(root).unwrap_or(path);
    if let Some(includes) = includes
        && !includes.is_match(relative)
    {
        return Ok(None);
    }
    if is_excluded(relative, excludes) {
        return Ok(None);
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == ErrorKind::InvalidData => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let display = display_path(path, relative);
    if vord_rules_engine::is_vendored_path(&display) {
        return Ok(None);
    }
    Ok(SourceFile::new(display, content, language).ok())
}

fn is_excluded(relative: &Path, excludes: &GlobSet) -> bool {
    excludes.is_match(relative)
}

/// `SourceFile::new` rejects absolute paths, so when `root` itself is a
/// single file (there's no meaningful subpath to strip it to) fall back to
/// the full path with any leading `/` stripped, rather than silently
/// dropping every file whenever `root` is passed as an absolute file path
/// (e.g. `vord scan /abs/path/to/file.ts`).
fn display_path(path: &Path, relative: &Path) -> String {
    if relative.as_os_str().is_empty() {
        path.to_string_lossy().trim_start_matches('/').to_string()
    } else {
        relative.to_string_lossy().to_string()
    }
}

fn build_globset(patterns: &[String]) -> Result<GlobSet, SourceLoadError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|e| SourceLoadError::InvalidExclusion(pattern.clone(), e))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| SourceLoadError::InvalidExclusion(String::new(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_a_single_file_given_by_absolute_path() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.ts");
        std::fs::write(&file, "eval(x);\n").unwrap();

        let absolute = file.canonicalize().unwrap();
        let sources = collect_sources(&absolute).unwrap();

        assert_eq!(sources.len(), 1, "expected the single file to be scanned");
        assert!(
            !sources[0].path().starts_with('/'),
            "path must not be absolute: {}",
            sources[0].path()
        );
        assert_eq!(sources[0].content(), "eval(x);\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exclusions_skip_matching_files_but_keep_the_rest() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-excl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("fixtures")).unwrap();
        std::fs::write(dir.join("fixtures/vulnerable.ts"), "eval(x);\n").unwrap();
        std::fs::write(dir.join("app.ts"), "const x = 1;\n").unwrap();

        let excluded = vec!["**/fixtures/**".to_string()];
        let sources = collect_sources_excluding(&dir, &excluded).unwrap();

        assert_eq!(sources.len(), 1, "expected only the non-excluded file");
        assert_eq!(sources[0].path(), "app.ts");

        // With no exclusions, both files are collected.
        assert_eq!(collect_sources(&dir).unwrap().len(), 2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inclusions_keep_only_matching_files() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-incl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("scripts")).unwrap();
        std::fs::write(dir.join("src/app.ts"), "const x = 1;\n").unwrap();
        std::fs::write(dir.join("scripts/build.ts"), "const y = 2;\n").unwrap();

        let included = vec!["src/**".to_string()];
        let sources = collect_sources_scoped(&dir, &[], &included, &[]).unwrap();

        assert_eq!(sources.len(), 1, "expected only the included file");
        assert_eq!(sources[0].path(), "src/app.ts");

        // An empty `inclusions` keeps every file, same as before this
        // parameter existed.
        assert_eq!(
            collect_sources_scoped(&dir, &[], &[], &[]).unwrap().len(),
            2
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_exclusion_glob_is_reported_as_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-bad-glob-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let bad = vec!["[".to_string()];
        assert!(collect_sources_excluding(&dir, &bad).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scans_a_single_file_given_by_relative_path() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-rel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.ts");
        std::fs::write(&file, "eval(x);\n").unwrap();

        let sources = collect_sources(&file).unwrap();

        assert_eq!(sources.len(), 1);
        assert!(!sources[0].path().starts_with('/'));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vendored_files_are_skipped_during_collection() {
        let dir = std::env::temp_dir().join(format!(
            "vord-collect-sources-vendor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("node_modules/lodash")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("node_modules/lodash/index.js"),
            "module.exports = {};\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/app.ts"), "const x = 1;\n").unwrap();

        let sources = collect_sources(&dir).unwrap();

        assert_eq!(sources.len(), 1, "vendored file should be skipped");
        assert_eq!(sources[0].path(), "src/app.ts");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
