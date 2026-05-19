//! `aex-conformance` — run the AEX v2 conformance suite and emit a
//! pass/fail report.
//!
//! See ADR-0048 for the policy: open Apache-2.0, the same test set
//! runs in CI of every AEX-conformant control plane.

use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use aex_conformance::{run_all, ConformanceResult, Outcome};

#[derive(Parser, Debug)]
#[command(
    name = "aex-conformance",
    about = "Run the AEX v2 conformance test suite",
    version
)]
struct Cli {
    /// Emit a JSON report to the given path in addition to stdout.
    #[arg(long)]
    report_json: Option<std::path::PathBuf>,

    /// Print only the summary line; one line per test → silent.
    #[arg(long)]
    quiet: bool,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    total: usize,
    passed: usize,
    failed: usize,
    tests: Vec<JsonTest<'a>>,
}

#[derive(Serialize)]
struct JsonTest<'a> {
    id: &'a str,
    category: &'a str,
    outcome: &'a str,
    message: Option<&'a str>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let results = run_all().await;
    if !cli.quiet {
        print_human(&results);
    }
    let (passed, failed) = count(&results);
    let total = results.len();

    if let Some(path) = cli.report_json.as_ref() {
        if let Err(e) = write_json(path, &results, passed, failed) {
            eprintln!("warning: failed to write JSON report: {}", e);
        }
    }

    println!();
    println!("──────────────────────────────────────────────────");
    if failed == 0 {
        println!("ALL PASSED — {} tests", total);
        println!("You can claim AEX v2 compliance.");
        ExitCode::SUCCESS
    } else {
        println!("FAILED — {} of {} tests failed", failed, total);
        ExitCode::FAILURE
    }
}

fn print_human(results: &[ConformanceResult]) {
    let mut current_cat: Option<&str> = None;
    for r in results {
        if current_cat != Some(r.category) {
            println!();
            println!("# {}", r.category);
            current_cat = Some(r.category);
        }
        match &r.outcome {
            Outcome::Pass => println!("  ✓ {}", r.id),
            Outcome::Fail(msg) => println!("  ✗ {} — {}", r.id, msg),
        }
    }
}

fn count(results: &[ConformanceResult]) -> (usize, usize) {
    let mut passed = 0;
    let mut failed = 0;
    for r in results {
        if r.outcome.is_pass() {
            passed += 1
        } else {
            failed += 1
        }
    }
    (passed, failed)
}

fn write_json(
    path: &std::path::Path,
    results: &[ConformanceResult],
    passed: usize,
    failed: usize,
) -> std::io::Result<()> {
    let tests: Vec<JsonTest> = results
        .iter()
        .map(|r| match &r.outcome {
            Outcome::Pass => JsonTest {
                id: r.id,
                category: r.category,
                outcome: "pass",
                message: None,
            },
            Outcome::Fail(msg) => JsonTest {
                id: r.id,
                category: r.category,
                outcome: "fail",
                message: Some(msg.as_str()),
            },
        })
        .collect();
    let report = JsonReport {
        total: results.len(),
        passed,
        failed,
        tests,
    };
    let json = serde_json::to_string_pretty(&report).expect("JSON serialization");
    std::fs::write(path, json)
}
