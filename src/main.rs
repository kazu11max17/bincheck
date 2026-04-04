use std::process;

use clap::Parser;

use bincheck::check::{CheckResult, check_file};
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
}

fn main() {
    let cli = Cli::parse();

    let is_table = cli.format != "json" && cli.format != "sarif";
    let output_format = match cli.format.as_str() {
        "json" => OutputFormat::Json,
        "sarif" => OutputFormat::Sarif,
        _ => OutputFormat::Table,
    };

    let mut results: Vec<CheckResult> = Vec::new();
    let mut has_errors = false;

    for path in &cli.files {
        match check_file(path) {
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
        let any_fail = results.iter().any(|r| r.has_failures());
        if any_fail || has_errors {
            process::exit(1);
        }
    } else if has_errors && results.is_empty() {
        process::exit(1);
    }
}
