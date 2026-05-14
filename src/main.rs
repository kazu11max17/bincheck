use std::path::PathBuf;
use std::process;

use clap::Parser;

use bincheck::banned::{default_list, load_from_json, merge};
use bincheck::check::{CheckOptions, CheckResult, check_file_with_options};
use bincheck::output::{OutputFormat, format_results};

#[derive(Parser)]
#[command(
    name = "bincheck",
    version,
    about = "Fast binary security property checker for ELF, PE, and Mach-O files"
)]
struct Cli {
    /// Binary files to check
    #[arg(required = true)]
    files: Vec<String>,

    /// Output format
    #[arg(short, long, default_value = "table", value_parser = ["table", "json", "sarif"])]
    format: String,

    /// Exit with code 1 if any check fails
    #[arg(long)]
    strict: bool,

    /// F1 (BHC010): JSON file with extra banned functions to merge with the
    /// default list. Format: `[{"name": "foo", "severity": "HIGH|MEDIUM|LOW"}]`.
    /// Same-name entries override the default severity.
    #[arg(long, value_name = "FILE")]
    banned_functions: Option<PathBuf>,

    /// F1 (BHC010): JSON file that **replaces** the default banned list.
    /// Mutually exclusive with `--banned-functions`. Same format.
    #[arg(long, value_name = "FILE", conflicts_with = "banned_functions")]
    banned_functions_replace: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    let is_table = cli.format != "json" && cli.format != "sarif";
    let output_format = match cli.format.as_str() {
        "json" => OutputFormat::Json,
        "sarif" => OutputFormat::Sarif,
        _ => OutputFormat::Table,
    };

    // F1: assemble banned-function list (default + optional overlay or replace).
    let banned = match (
        cli.banned_functions.as_ref(),
        cli.banned_functions_replace.as_ref(),
    ) {
        (None, None) => default_list(),
        (Some(p), None) => match load_from_json(p) {
            Ok(overlay) => merge(default_list(), overlay),
            Err(e) => {
                eprintln!("--banned-functions: {}", e);
                process::exit(2);
            }
        },
        (None, Some(p)) => match load_from_json(p) {
            Ok(replacement) => replacement,
            Err(e) => {
                eprintln!("--banned-functions-replace: {}", e);
                process::exit(2);
            }
        },
        (Some(_), Some(_)) => unreachable!("clap conflicts_with should prevent this"),
    };
    let opts = CheckOptions {
        banned_functions: Some(banned),
    };

    let mut results: Vec<CheckResult> = Vec::new();
    let mut has_errors = false;

    for path in &cli.files {
        match check_file_with_options(path, &opts) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("Error processing {}: {}", path, e);
                has_errors = true;
            }
        }
    }

    let output = format_results(&results, output_format);
    println!("{}", output);

    // Print summary line for table output when multiple files are checked
    if is_table && (results.len() + if has_errors { 1 } else { 0 }) > 1 {
        let passed = results.iter().filter(|r| !r.has_failures()).count();
        let failed = results.iter().filter(|r| r.has_failures()).count();
        let errors = if has_errors {
            cli.files.len() - results.len()
        } else {
            0
        };
        let total = results.len() + errors;
        let mut parts = vec![format!("{} files checked", total)];
        parts.push(format!("{} passed", passed));
        if failed > 0 {
            parts.push(format!("{} failed", failed));
        }
        if errors > 0 {
            parts.push(format!("{} errors", errors));
        }
        eprintln!("{}", parts.join(", "));
    }

    if cli.strict {
        // --strict promotes warnings (currently SUID/SGID, BHC011) to exit-1 alongside
        // the existing failure conditions. Without --strict, SUID/SGID is informational.
        let any_fail = results.iter().any(|r| r.has_failures() || r.has_warnings());
        if any_fail || has_errors {
            process::exit(1);
        }
    } else if has_errors && results.is_empty() {
        process::exit(1);
    }
}
