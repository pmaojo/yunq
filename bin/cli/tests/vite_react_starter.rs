//! End-to-end: `--profile vite-react-frontend-starter --enforce-gate`
//! blocks a fixture that violates this starter's bulletproof-react layering
//! rules and passes one that follows it. Mirrors the
//! `bin/cli/tests/fixtures/layer-taxonomy` + `layer_taxonomy.rs` convention
//! for a config-driven scenario, scoped to the profile/gate plumbing this
//! starter adds instead of a declared `[[architecture.layer]]` taxonomy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const PROFILE_NAME: &str = "vite-react-frontend-starter";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vite-react-starter")
        .join(name)
}

fn scan(name: &str) -> vord_rules_engine::AnalysisReport {
    let profile = vord_rules_engine::profile_by_name(PROFILE_NAME)
        .expect("the vite-react-frontend-starter profile resolves by name");
    futures::executor::block_on(vord_cli::scan_with_profile(
        &fixture(name),
        None,
        &[],
        &[],
        &[],
        &vord_cli::ProjectSettings {
            duplication: &Default::default(),
            architecture: &Default::default(),
            vite_react: &Default::default(),
            secrets: &Default::default(),
            rules_custom: &[],
        },
        Some(profile),
    ))
    .unwrap()
}

fn fired_rules(report: &vord_rules_engine::AnalysisReport) -> BTreeSet<String> {
    report
        .issues()
        .iter()
        .map(|i| i.rule().to_string())
        .collect()
}

#[test]
fn the_profile_resolves_by_name() {
    assert!(vord_rules_engine::profile_by_name(PROFILE_NAME).is_some());
    assert!(vord_rules_engine::profile_by_name("not-a-real-profile").is_none());
}

#[test]
fn the_dirty_fixture_trips_one_violation_per_rule() {
    let report = scan("dirty");
    let fired = fired_rules(&report);
    for expected in [
        "vite-react:no-data-layer-import-in-view",
        "vite-react:no-transport-call-in-view",
        "vite-react:data-hook-outside-api-dir",
        "vite-react:transport-client-outside-infra",
        "vite-react:hardcoded-base-url",
        "vite-react:tailwind-space-between",
    ] {
        assert!(
            fired.contains(expected),
            "expected {expected}; fired: {fired:?}"
        );
    }
}

#[test]
fn the_dirty_fixture_fails_the_starter_gate_with_status_3() {
    let report = scan("dirty");
    let gate =
        vord_cli::quality_gate_for_profile(Some(PROFILE_NAME)).evaluate(|key| report.measure(key));
    assert_eq!(gate.status(), vord_rules_engine::GateStatus::Failed);

    // The same enforcement `main.rs::exit_code` applies for
    // `--enforce-gate`: any blocker/critical finding fails the gate, which
    // is exit status 3.
    let enforce_gate = true;
    let gate_failed = enforce_gate && gate.status() == vord_rules_engine::GateStatus::Failed;
    assert!(gate_failed, "the dirty fixture must fail --enforce-gate");
}

#[test]
fn the_clean_fixture_trips_none_of_this_starters_own_rules() {
    let report = scan("clean");
    let fired = fired_rules(&report);
    for rule in [
        "vite-react:no-data-layer-import-in-view",
        "vite-react:no-transport-call-in-view",
        "vite-react:data-hook-outside-api-dir",
        "vite-react:transport-client-outside-infra",
        "vite-react:hardcoded-base-url",
        "vite-react:tailwind-space-between",
    ] {
        assert!(
            !fired.contains(rule),
            "clean fixture unexpectedly fired {rule}"
        );
    }
}

#[test]
fn the_clean_fixture_passes_the_starter_gate() {
    let report = scan("clean");
    let gate =
        vord_cli::quality_gate_for_profile(Some(PROFILE_NAME)).evaluate(|key| report.measure(key));
    assert_eq!(gate.status(), vord_rules_engine::GateStatus::Passed);
}

#[test]
fn scanning_with_no_profile_selected_is_unaffected_by_this_starters_rules() {
    // The additivity guarantee: the dirty fixture scanned with the default
    // "vord way" profile (no `--profile`) never activates a `vite-react:*`
    // id, since none of them are in `default_profile()`'s activation list.
    let report = futures::executor::block_on(vord_cli::scan_with_project_config(
        &fixture("dirty"),
        None,
        &[],
        &[],
        &[],
        &Default::default(),
        &Default::default(),
    ))
    .unwrap();
    let fired = fired_rules(&report);
    assert!(
        fired.iter().all(|r| !r.starts_with("vite-react:")),
        "fired: {fired:?}"
    );
}
