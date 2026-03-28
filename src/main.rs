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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Check one or more binary files for security properties
    Check(CheckArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
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

/// Also allow files directly without the "check" subcommand
#[derive(Parser)]
#[command(
    name = "bincheck",
    version,
    about = "Fast binary security property checker for ELF, PE, and Mach-O files"
)]
struct CliFallback {
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
    let (files, format_str, strict) = match Cli::try_parse() {
        Ok(cli) => match cli.command {
            Some(Command::Check(args)) => (args.files, args.format, args.strict),
            None => {
                // No subcommand given, re-parse as fallback
                let fb = CliFallback::parse();
                (fb.files, fb.format, fb.strict)
            }
        },
        Err(_) => {
            // Try fallback parse (direct file arguments)
            let fb = CliFallback::parse();
            (fb.files, fb.format, fb.strict)
        }
    };

    let output_format = match format_str.as_str() {
        "json" => OutputFormat::Json,
        "sarif" => OutputFormat::Sarif,
        _ => OutputFormat::Table,
    };

    let mut results: Vec<CheckResult> = Vec::new();
    let mut has_errors = false;

    for path in &files {
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

    if strict {
        let any_fail = results.iter().any(|r| r.has_failures());
        if any_fail || has_errors {
            process::exit(1);
        }
    } else if has_errors && results.is_empty() {
        process::exit(1);
    }
}
