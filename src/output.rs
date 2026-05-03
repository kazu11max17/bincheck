use chrono::Utc;
use colored::Colorize;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::Serialize;

use crate::check::{CheckResult, FileModeStatus, FormatResult};
use crate::elf::{Linkage, RelroStatus};
use crate::pe::SafeSehStatus;

/// Output format selection
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
}

/// Format all check results according to the selected output format
pub fn format_results(results: &[CheckResult], format: OutputFormat) -> String {
    match format {
        OutputFormat::Table => format_table(results),
        OutputFormat::Json => format_json(results),
        OutputFormat::Sarif => format_sarif(results),
    }
}

fn pass_label() -> String {
    "PASS".green().to_string()
}

fn fail_label() -> String {
    "FAIL".red().to_string()
}

fn warn_label() -> String {
    "WARN".yellow().to_string()
}

fn status_cell(pass: bool) -> String {
    if pass { pass_label() } else { fail_label() }
}

fn format_table(results: &[CheckResult]) -> String {
    let mut output = String::new();

    for result in results {
        output.push_str(&format!(
            "{} {} ({})\n",
            "File:".bold(),
            result.file_path,
            result.format
        ));

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec![
            Cell::new("Property"),
            Cell::new("Status"),
            Cell::new("Details"),
        ]);

        match &result.result {
            FormatResult::Elf(elf) => {
                let relro_pass = elf.relro == RelroStatus::Full;
                let relro_status = if relro_pass {
                    pass_label()
                } else if elf.relro == RelroStatus::Partial {
                    warn_label()
                } else {
                    fail_label()
                };
                table.add_row(vec![
                    Cell::new("RELRO"),
                    Cell::new(relro_status),
                    Cell::new(elf.relro.to_string()),
                ]);
                table.add_row(vec![
                    Cell::new("Stack Canary"),
                    Cell::new(status_cell(elf.stack_canary)),
                    Cell::new(if elf.stack_canary {
                        "__stack_chk_fail found"
                    } else {
                        ""
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("NX"),
                    Cell::new(status_cell(elf.nx)),
                    Cell::new(if elf.nx {
                        "Stack not executable"
                    } else {
                        "Stack executable!"
                    }),
                ]);
                let pie_details = match (&elf.linkage, elf.pie) {
                    (Some(Linkage::StaticPie), _) => {
                        if elf.df_1_pie {
                            "ET_DYN (static-pie, DF_1_PIE)".to_string()
                        } else {
                            "ET_DYN (static-pie)".to_string()
                        }
                    }
                    (_, true) => "ET_DYN".to_string(),
                    (_, false) => "ET_EXEC".to_string(),
                };
                table.add_row(vec![
                    Cell::new("PIE"),
                    Cell::new(status_cell(elf.pie)),
                    Cell::new(pie_details),
                ]);
                let linkage_details = match &elf.linkage {
                    Some(l) => l.to_string(),
                    None => "unknown".to_string(),
                };
                table.add_row(vec![
                    Cell::new("Linkage"),
                    Cell::new("INFO".cyan().to_string()),
                    Cell::new(linkage_details),
                ]);
                table.add_row(vec![
                    Cell::new("Fortify Source"),
                    Cell::new(status_cell(elf.fortify_source)),
                    Cell::new(if elf.fortify_source {
                        elf.fortified_functions.join(", ")
                    } else {
                        String::new()
                    }),
                ]);

                // RPATH/RUNPATH warnings
                let rpath_status = if elf.rpath.is_some() {
                    warn_label()
                } else {
                    pass_label()
                };
                table.add_row(vec![
                    Cell::new("RPATH"),
                    Cell::new(rpath_status),
                    Cell::new(elf.rpath.as_deref().unwrap_or("Not set")),
                ]);
                let runpath_status = if elf.runpath.is_some() {
                    warn_label()
                } else {
                    pass_label()
                };
                table.add_row(vec![
                    Cell::new("RUNPATH"),
                    Cell::new(runpath_status),
                    Cell::new(elf.runpath.as_deref().unwrap_or("Not set")),
                ]);

                // Debug info warnings
                let debug_status = if elf.debug_info.has_debug_info() {
                    warn_label()
                } else {
                    pass_label()
                };
                let debug_details = if !elf.debug_info.dwarf_sections.is_empty() {
                    format!("DWARF: {}", elf.debug_info.dwarf_sections.join(", "))
                } else if elf.debug_info.has_symtab {
                    "Unstripped (symtab present)".to_string()
                } else {
                    "No debug info".to_string()
                };
                table.add_row(vec![
                    Cell::new("Debug Info"),
                    Cell::new(debug_status),
                    Cell::new(debug_details),
                ]);

                let symtab_status = if elf.debug_info.has_symtab {
                    warn_label()
                } else {
                    pass_label()
                };
                table.add_row(vec![
                    Cell::new("Symbol Table"),
                    Cell::new(symtab_status),
                    Cell::new(if elf.debug_info.has_symtab {
                        "Unstripped (.symtab present)"
                    } else {
                        "Stripped"
                    }),
                ]);

                if let Some(ref _build_id) = elf.debug_info.build_id {
                    table.add_row(vec![
                        Cell::new("Build ID"),
                        Cell::new("INFO".cyan().to_string()),
                        Cell::new(".note.gnu.build-id present"),
                    ]);
                }
            }
            FormatResult::Pe(pe) => {
                table.add_row(vec![
                    Cell::new("ASLR"),
                    Cell::new(status_cell(pe.aslr)),
                    Cell::new(if pe.aslr { "DYNAMIC_BASE" } else { "" }),
                ]);
                table.add_row(vec![
                    Cell::new("High Entropy ASLR"),
                    Cell::new(status_cell(pe.high_entropy_aslr)),
                    Cell::new(if pe.high_entropy_aslr {
                        "HIGH_ENTROPY_VA"
                    } else {
                        ""
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("DEP/NX"),
                    Cell::new(status_cell(pe.dep_nx)),
                    Cell::new(if pe.dep_nx { "NX_COMPAT" } else { "" }),
                ]);
                let cfg_status = if pe.cfg { pass_label() } else { warn_label() };
                table.add_row(vec![
                    Cell::new("CFG"),
                    Cell::new(cfg_status),
                    Cell::new(if pe.cfg {
                        "GUARD_CF"
                    } else {
                        "Not enabled (optional)"
                    }),
                ]);
                let (seh_pass, seh_detail) = match &pe.safe_seh {
                    SafeSehStatus::Enabled => (true, "SEHandler table present"),
                    SafeSehStatus::NotFound => (false, "No SEHandler table (32-bit)"),
                    SafeSehStatus::NotApplicable => (true, "N/A (64-bit)"),
                    SafeSehStatus::NoSeh => (true, "NO_SEH (disabled)"),
                };
                table.add_row(vec![
                    Cell::new("SafeSEH"),
                    Cell::new(status_cell(seh_pass)),
                    Cell::new(seh_detail),
                ]);
                table.add_row(vec![
                    Cell::new("Authenticode"),
                    Cell::new(status_cell(pe.authenticode)),
                    Cell::new(if pe.authenticode {
                        "Signed"
                    } else {
                        "Not signed"
                    }),
                ]);

                // Debug info warnings
                let debug_status = if pe.debug_info.has_debug_info() {
                    warn_label()
                } else {
                    pass_label()
                };
                let debug_details = if let Some(ref pdb) = pe.debug_info.pdb_path {
                    format!("Debug directory present, PDB: {}", pdb)
                } else if pe.debug_info.has_debug_directory {
                    "Debug directory present".to_string()
                } else {
                    "No debug info".to_string()
                };
                table.add_row(vec![
                    Cell::new("Debug Info"),
                    Cell::new(debug_status),
                    Cell::new(debug_details),
                ]);
            }
            FormatResult::MachO(macho) => {
                table.add_row(vec![
                    Cell::new("PIE"),
                    Cell::new(status_cell(macho.pie)),
                    Cell::new(if macho.pie { "MH_PIE" } else { "" }),
                ]);
                table.add_row(vec![
                    Cell::new("Stack Canary"),
                    Cell::new(status_cell(macho.stack_canary)),
                    Cell::new(if macho.stack_canary {
                        "___stack_chk_fail/guard found"
                    } else {
                        ""
                    }),
                ]);
                let arc_status = if macho.arc {
                    pass_label()
                } else {
                    warn_label()
                };
                table.add_row(vec![
                    Cell::new("ARC"),
                    Cell::new(arc_status),
                    Cell::new(if macho.arc {
                        "_objc_release found"
                    } else {
                        "Not detected (informational, ObjC only)"
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("NX Stack"),
                    Cell::new(status_cell(macho.nx_stack)),
                    Cell::new(if macho.nx_stack {
                        "Stack not executable"
                    } else {
                        "Stack executable!"
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("NX Heap"),
                    Cell::new(status_cell(macho.nx_heap)),
                    Cell::new(if macho.nx_heap {
                        "__DATA not executable"
                    } else {
                        "__DATA executable!"
                    }),
                ]);
                let codesig_status = if macho.code_signature {
                    pass_label()
                } else {
                    warn_label()
                };
                table.add_row(vec![
                    Cell::new("Code Signature"),
                    Cell::new(codesig_status),
                    Cell::new(if macho.code_signature {
                        "LC_CODE_SIGNATURE present"
                    } else {
                        "Not signed (optional)"
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("Hardened Runtime"),
                    Cell::new(status_cell(macho.hardened_runtime)),
                    Cell::new(if macho.hardened_runtime {
                        "CS_RUNTIME enabled"
                    } else {
                        ""
                    }),
                ]);
                table.add_row(vec![
                    Cell::new("Restrict Segment"),
                    Cell::new(status_cell(macho.restrict_segment)),
                    Cell::new(if macho.restrict_segment {
                        "__RESTRICT,__restrict present"
                    } else {
                        ""
                    }),
                ]);
            }
            FormatResult::Unsupported => {
                table.add_row(vec![
                    Cell::new("N/A"),
                    Cell::new(fail_label()),
                    Cell::new("Unsupported binary format"),
                ]);
            }
        }

        // F2 (BHC011): file-level SUID/SGID row, appended for all formats so the
        // user always sees the bit they may have set unintentionally.
        if let Some(fm) = &result.file_mode {
            let (status_label, details) = match fm.status {
                FileModeStatus::Normal => (pass_label(), "no SUID/SGID".to_string()),
                FileModeStatus::Suid => (warn_label(), "SUID set (04000)".to_string()),
                FileModeStatus::Sgid => (warn_label(), "SGID set (02000)".to_string()),
                FileModeStatus::SuidSgid => (warn_label(), "SUID + SGID set (06000)".to_string()),
                FileModeStatus::Symlink => ("INFO".cyan().to_string(), "symlink".to_string()),
                FileModeStatus::NotApplicable => (
                    "N/A".dimmed().to_string(),
                    "platform-not-supported".to_string(),
                ),
            };
            table.add_row(vec![
                Cell::new("File Mode"),
                Cell::new(status_label),
                Cell::new(details),
            ]);
        }

        output.push_str(&table.to_string());
        output.push('\n');
    }

    output
}

fn format_json(results: &[CheckResult]) -> String {
    let output = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now().to_rfc3339(),
        "results": results,
    });
    serde_json::to_string_pretty(&output).unwrap_or_else(|e| format!("JSON error: {}", e))
}

/// SARIF v2.1.0 output for CI integration
#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "helpUri")]
    help_uri: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    fingerprints: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

fn rule_help_uri(rule_id: &str) -> String {
    let base = "https://github.com/kazu11max17/bincheck";
    let fragment = match rule_id {
        "BHC001" => "#relro",
        "BHC002" => "#stack-canary",
        "BHC003" => "#nx-dep",
        "BHC004" => "#pie-aslr",
        "BHC005" => "#fortify-source",
        "BHC006" | "BHC007" => "#rpath-runpath",
        "BHC011" => "#suid-sgid",
        "BHC013" => "#static-pie",
        "BHC104" => "#cfg",
        "BHC105" => "#safeseh",
        "BHC206" => "#code-signature",
        _ => "",
    };
    format!("{}{}", base, fragment)
}

/// Determine SARIF level based on rule_id and check context (details for RELRO partial).
fn rule_level(rule_id: &str, details: &str, warn_only: bool) -> &'static str {
    if warn_only {
        return "note";
    }
    match rule_id {
        // RELRO: None → error, Partial → warning
        "BHC001" => {
            if details == "Partial" {
                "warning"
            } else {
                "error"
            }
        }
        // Stack Canary missing → error
        "BHC002" => "error",
        // NX missing → error
        "BHC003" => "error",
        // PIE missing → error (ELF)
        "BHC004" => "error",
        // Fortify Source missing → warning
        "BHC005" => "warning",
        // RPATH/RUNPATH present → warning
        "BHC006" | "BHC007" => "warning",
        // SUID/SGID present → warning (informational; --strict promotes to exit 1)
        "BHC011" => "warning",
        // Linkage classification → note (informational only)
        "BHC013" => "note",
        // SafeSEH missing (PE) → warning
        "BHC105" => "warning",
        // PIE missing (Mach-O) → error
        "BHC201" => "error",
        // Stack Canary missing (Mach-O) → error
        "BHC202" => "error",
        // NX Stack missing → error
        "BHC204" => "error",
        // NX Heap missing → error
        "BHC205" => "error",
        // default → warning
        _ => "warning",
    }
}

fn format_sarif(results: &[CheckResult]) -> String {
    let mut sarif_results = Vec::new();
    let mut rules = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for result in results {
        let checks = collect_check_items(result);
        for (rule_id, name, pass, details, warn_only) in checks {
            if !seen_rules.contains(&rule_id) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    name: name.clone(),
                    short_description: SarifMessage {
                        text: format!("Binary hardening check: {}", name),
                    },
                    help_uri: rule_help_uri(&rule_id),
                });
                seen_rules.insert(rule_id.clone());
            }

            if !pass {
                let level = rule_level(&rule_id, &details, warn_only).to_string();
                let msg = if warn_only {
                    if details.is_empty() {
                        format!("{} not enabled (informational)", name)
                    } else {
                        format!("{} not enabled (informational): {}", name, details)
                    }
                } else if details.is_empty() {
                    format!("{} check failed", name)
                } else {
                    format!("{} check failed: {}", name, details)
                };
                let mut fingerprints = std::collections::HashMap::new();
                fingerprints.insert("binaryPath/v1".to_string(), result.file_path.clone());
                sarif_results.push(SarifResult {
                    rule_id,
                    level,
                    message: SarifMessage { text: msg },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: result.file_path.clone(),
                            },
                        },
                    }],
                    fingerprints,
                });
            }
        }
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "bincheck".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/kazu11max17/bincheck".to_string(),
                    rules,
                },
            },
            results: sarif_results,
        }],
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("SARIF error: {}", e))
}

/// Collect (rule_id, name, pass, details, warn_only) tuples from a check result.
/// warn_only=true means the item is informational and should use "note" level in SARIF.
#[allow(clippy::type_complexity)]
fn collect_check_items(result: &CheckResult) -> Vec<(String, String, bool, String, bool)> {
    let mut items = Vec::new();

    match &result.result {
        FormatResult::Elf(elf) => {
            let relro_pass = elf.relro == RelroStatus::Full;
            items.push((
                "BHC001".to_string(),
                "RELRO".to_string(),
                relro_pass,
                elf.relro.to_string(),
                false,
            ));
            items.push((
                "BHC002".to_string(),
                "Stack Canary".to_string(),
                elf.stack_canary,
                String::new(),
                false,
            ));
            items.push((
                "BHC003".to_string(),
                "NX".to_string(),
                elf.nx,
                String::new(),
                false,
            ));
            items.push((
                "BHC004".to_string(),
                "PIE".to_string(),
                elf.pie,
                String::new(),
                false,
            ));
            items.push((
                "BHC005".to_string(),
                "Fortify Source".to_string(),
                elf.fortify_source,
                String::new(),
                false,
            ));
            // F4 (BHC013): linkage classification — informational, never a failure.
            // Surfacing it as a SARIF item lets downstream tooling key off the rule_id
            // even though we always pass=true (warn_only=true → "note" level on emit,
            // but emit only happens when pass=false; here we just register the rule).
            items.push((
                "BHC013".to_string(),
                "Linkage".to_string(),
                true,
                match &elf.linkage {
                    Some(l) => l.to_string(),
                    None => "unknown".to_string(),
                },
                true,
            ));
            items.push((
                "BHC006".to_string(),
                "RPATH".to_string(),
                !elf.rpath_is_failure(),
                elf.rpath.clone().unwrap_or_default(),
                false,
            ));
            items.push((
                "BHC007".to_string(),
                "RUNPATH".to_string(),
                !elf.runpath_is_failure(),
                elf.runpath.clone().unwrap_or_default(),
                false,
            ));
            items.push((
                "BHC008".to_string(),
                "Debug Info".to_string(),
                !elf.debug_info.has_debug_info(),
                if !elf.debug_info.dwarf_sections.is_empty() {
                    format!(
                        "DWARF sections: {}",
                        elf.debug_info.dwarf_sections.join(", ")
                    )
                } else if elf.debug_info.has_symtab {
                    "Unstripped (symtab present)".to_string()
                } else {
                    String::new()
                },
                false,
            ));
            items.push((
                "BHC009".to_string(),
                "Symbol Table".to_string(),
                !elf.debug_info.has_symtab,
                if elf.debug_info.has_symtab {
                    "Unstripped (.symtab present)".to_string()
                } else {
                    String::new()
                },
                false,
            ));
        }
        FormatResult::Pe(pe) => {
            items.push((
                "BHC101".to_string(),
                "ASLR".to_string(),
                pe.aslr,
                String::new(),
                false,
            ));
            items.push((
                "BHC102".to_string(),
                "High Entropy ASLR".to_string(),
                pe.high_entropy_aslr,
                String::new(),
                false,
            ));
            items.push((
                "BHC103".to_string(),
                "DEP/NX".to_string(),
                pe.dep_nx,
                String::new(),
                false,
            ));
            items.push((
                "BHC104".to_string(),
                "CFG".to_string(),
                pe.cfg,
                String::new(),
                true,
            ));
            items.push((
                "BHC105".to_string(),
                "SafeSEH".to_string(),
                pe.safe_seh != SafeSehStatus::NotFound,
                String::new(),
                false,
            ));
            items.push((
                "BHC106".to_string(),
                "Authenticode".to_string(),
                pe.authenticode,
                String::new(),
                false,
            ));
            items.push((
                "BHC107".to_string(),
                "Debug Info".to_string(),
                !pe.debug_info.has_debug_info(),
                if let Some(ref pdb) = pe.debug_info.pdb_path {
                    format!("PDB: {}", pdb)
                } else if pe.debug_info.has_debug_directory {
                    "Debug directory present".to_string()
                } else {
                    String::new()
                },
                false,
            ));
        }
        FormatResult::MachO(macho) => {
            items.push((
                "BHC201".to_string(),
                "PIE".to_string(),
                macho.pie,
                String::new(),
                false,
            ));
            items.push((
                "BHC202".to_string(),
                "Stack Canary".to_string(),
                macho.stack_canary,
                String::new(),
                false,
            ));
            items.push((
                "BHC203".to_string(),
                "ARC".to_string(),
                macho.arc,
                String::new(),
                true,
            ));
            items.push((
                "BHC204".to_string(),
                "NX Stack".to_string(),
                macho.nx_stack,
                String::new(),
                false,
            ));
            items.push((
                "BHC205".to_string(),
                "NX Heap".to_string(),
                macho.nx_heap,
                String::new(),
                false,
            ));
            items.push((
                "BHC206".to_string(),
                "Code Signature".to_string(),
                macho.code_signature,
                String::new(),
                true,
            ));
            items.push((
                "BHC207".to_string(),
                "Hardened Runtime".to_string(),
                macho.hardened_runtime,
                String::new(),
                false,
            ));
            items.push((
                "BHC208".to_string(),
                "Restrict Segment".to_string(),
                macho.restrict_segment,
                String::new(),
                false,
            ));
        }
        FormatResult::Unsupported => {
            items.push((
                "BHC000".to_string(),
                "Format".to_string(),
                false,
                "Unsupported binary format".to_string(),
                false,
            ));
        }
    }

    // F2 (BHC011): SUID/SGID at the file layer. pass=true on Normal/Symlink/N/A,
    // pass=false on Suid/Sgid/SuidSgid (warn_only=true so SARIF emits "note" — but
    // since `--strict` consumes `has_warnings()` separately, this row is purely
    // SARIF reporting). Symlink and N/A do not emit (pass=true).
    if let Some(fm) = &result.file_mode {
        let (pass, details) = match fm.status {
            FileModeStatus::Normal | FileModeStatus::Symlink | FileModeStatus::NotApplicable => {
                (true, String::new())
            }
            FileModeStatus::Suid => (false, "SUID set (04000)".to_string()),
            FileModeStatus::Sgid => (false, "SGID set (02000)".to_string()),
            FileModeStatus::SuidSgid => (false, "SUID + SGID set (06000)".to_string()),
        };
        items.push((
            "BHC011".to_string(),
            "SUID/SGID".to_string(),
            pass,
            details,
            true,
        ));
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{BinaryFormat, CheckResult, FormatResult};
    use crate::elf::{ElfCheckResult, ElfDebugInfo, RelroStatus};
    use crate::pe::{PeCheckResult, PeDebugInfo};

    fn no_elf_debug() -> ElfDebugInfo {
        ElfDebugInfo {
            dwarf_sections: vec![],
            has_symtab: false,
            has_strtab: false,
            build_id: None,
        }
    }

    fn no_pe_debug() -> PeDebugInfo {
        PeDebugInfo {
            has_debug_directory: false,
            pdb_path: None,
        }
    }

    fn sample_elf_result_all_pass() -> CheckResult {
        CheckResult {
            file_path: "/usr/bin/test".to_string(),
            format: BinaryFormat::Elf,
            result: FormatResult::Elf(ElfCheckResult {
                relro: RelroStatus::Full,
                stack_canary: true,
                nx: true,
                pie: true,
                fortify_source: true,
                fortified_functions: vec!["__printf_chk".to_string(), "__memcpy_chk".to_string()],
                fortify_level: Some(2),
                rpath: None,
                runpath: None,
                linkage: None,
                df_1_pie: false,
                debug_info: no_elf_debug(),
            }),
            file_mode: None,
        }
    }

    fn sample_elf_result_all_fail() -> CheckResult {
        CheckResult {
            file_path: "/tmp/vuln".to_string(),
            format: BinaryFormat::Elf,
            result: FormatResult::Elf(ElfCheckResult {
                relro: RelroStatus::None,
                stack_canary: false,
                nx: false,
                pie: false,
                fortify_source: false,
                fortified_functions: vec![],
                fortify_level: None,
                rpath: Some("/usr/local/lib".to_string()),
                runpath: Some("/opt/lib".to_string()),
                linkage: None,
                df_1_pie: false,
                debug_info: ElfDebugInfo {
                    dwarf_sections: vec![".debug_info".to_string(), ".debug_line".to_string()],
                    has_symtab: true,
                    has_strtab: true,
                    build_id: None,
                },
            }),
            file_mode: None,
        }
    }

    fn sample_pe_result() -> CheckResult {
        CheckResult {
            file_path: "C:\\test.exe".to_string(),
            format: BinaryFormat::Pe,
            result: FormatResult::Pe(PeCheckResult {
                aslr: true,
                high_entropy_aslr: false,
                dep_nx: true,
                cfg: false,
                safe_seh: SafeSehStatus::NotApplicable,
                authenticode: false,
                debug_info: no_pe_debug(),
            }),
            file_mode: None,
        }
    }

    fn sample_macho_result_all_pass() -> CheckResult {
        use crate::macho::MachoCheckResult;
        CheckResult {
            file_path: "/usr/bin/test_macho".to_string(),
            format: BinaryFormat::MachO,
            result: FormatResult::MachO(MachoCheckResult {
                pie: true,
                stack_canary: true,
                arc: true,
                nx_stack: true,
                nx_heap: true,
                code_signature: true,
                hardened_runtime: true,
                restrict_segment: true,
            }),
            file_mode: None,
        }
    }

    fn sample_macho_result_all_fail() -> CheckResult {
        use crate::macho::MachoCheckResult;
        CheckResult {
            file_path: "/tmp/vuln_macho".to_string(),
            format: BinaryFormat::MachO,
            result: FormatResult::MachO(MachoCheckResult {
                pie: false,
                stack_canary: false,
                arc: false,
                nx_stack: false,
                nx_heap: false,
                code_signature: false,
                hardened_runtime: false,
                restrict_segment: false,
            }),
            file_mode: None,
        }
    }

    fn sample_unsupported_result() -> CheckResult {
        CheckResult {
            file_path: "test.bin".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: None,
        }
    }

    // ---- JSON output ----

    #[test]
    fn json_output_valid_json() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("JSON output should be valid JSON");
        assert!(parsed.is_object());
        assert!(parsed["results"].is_array());
        assert_eq!(parsed["results"].as_array().unwrap().len(), 1);
        assert!(parsed["version"].is_string());
        assert!(parsed["timestamp"].is_string());
    }

    #[test]
    fn json_output_contains_file_path() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Json);
        assert!(output.contains("/usr/bin/test"));
    }

    #[test]
    fn json_output_multiple_results() {
        let results = vec![sample_elf_result_all_pass(), sample_pe_result()];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_output_empty_results() {
        let results: Vec<CheckResult> = vec![];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_output_elf_fields() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let elf = &parsed["results"][0]["result"]["Elf"];
        assert_eq!(elf["relro"], "Full");
        assert_eq!(elf["stack_canary"], true);
        assert_eq!(elf["nx"], true);
        assert_eq!(elf["pie"], true);
        assert_eq!(elf["fortify_source"], true);
    }

    #[test]
    fn json_output_pe_fields() {
        let results = vec![sample_pe_result()];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let pe = &parsed["results"][0]["result"]["Pe"];
        assert_eq!(pe["aslr"], true);
        assert_eq!(pe["high_entropy_aslr"], false);
        assert_eq!(pe["dep_nx"], true);
        assert_eq!(pe["cfg"], false);
    }

    // ---- Table output ----

    #[test]
    fn table_output_contains_file_info() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("/usr/bin/test"));
        assert!(output.contains("ELF"));
    }

    #[test]
    fn table_output_contains_elf_properties() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("RELRO"));
        assert!(output.contains("Stack Canary"));
        assert!(output.contains("NX"));
        assert!(output.contains("PIE"));
        assert!(output.contains("Fortify Source"));
        assert!(output.contains("RPATH"));
        assert!(output.contains("RUNPATH"));
    }

    #[test]
    fn table_output_contains_pe_properties() {
        let results = vec![sample_pe_result()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("ASLR"));
        assert!(output.contains("DEP/NX"));
        assert!(output.contains("CFG"));
        assert!(output.contains("SafeSEH"));
        assert!(output.contains("Authenticode"));
    }

    #[test]
    fn table_output_unsupported_format() {
        let results = vec![sample_unsupported_result()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("Unsupported binary format"));
    }

    #[test]
    fn table_output_empty() {
        let results: Vec<CheckResult> = vec![];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.is_empty());
    }

    #[test]
    fn table_output_elf_with_rpath() {
        let results = vec![sample_elf_result_all_fail()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("/usr/local/lib"));
        assert!(output.contains("/opt/lib"));
    }

    #[test]
    fn table_output_elf_fortified_functions_listed() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("__printf_chk"));
        assert!(output.contains("__memcpy_chk"));
    }

    // ---- SARIF output ----

    #[test]
    fn sarif_output_valid_json() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF should be valid JSON");
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    }

    #[test]
    fn sarif_output_tool_info() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let driver = &parsed["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "bincheck");
        assert!(
            driver["informationUri"]
                .as_str()
                .unwrap()
                .contains("bincheck")
        );
    }

    #[test]
    fn sarif_no_failures_means_no_results() {
        let results = vec![sample_elf_result_all_pass()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        // All checks pass, so no SARIF results (only failures are reported)
        assert!(
            sarif_results.is_empty(),
            "No failures should mean no SARIF results"
        );
    }

    #[test]
    fn sarif_failures_produce_results() {
        let results = vec![sample_elf_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        // Multiple failures should produce multiple SARIF results
        assert!(
            !sarif_results.is_empty(),
            "Failures should produce SARIF results"
        );

        // Check that result contains file location
        // First result is RELRO None which maps to "error" level
        let first = &sarif_results[0];
        assert!(
            first["level"] == "error" || first["level"] == "warning",
            "level should be error or warning, got: {}",
            first["level"]
        );
        let uri = &first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert_eq!(uri, "/tmp/vuln");
    }

    #[test]
    fn sarif_rules_populated() {
        let results = vec![sample_elf_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        // Should have rules for all ELF checks
        assert!(rules.len() >= 7, "Should have at least 7 ELF rules");

        // Verify rule IDs follow the BHC pattern
        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(rule_ids.contains(&"BHC001")); // RELRO
        assert!(rule_ids.contains(&"BHC002")); // Stack Canary
        assert!(rule_ids.contains(&"BHC003")); // NX
        assert!(rule_ids.contains(&"BHC004")); // PIE
    }

    #[test]
    fn sarif_pe_rule_ids() {
        let results = vec![sample_pe_result()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(rule_ids.contains(&"BHC101")); // ASLR
        assert!(rule_ids.contains(&"BHC103")); // DEP/NX
        assert!(rule_ids.contains(&"BHC104")); // CFG
    }

    #[test]
    fn sarif_pe_cfg_is_note_level() {
        // CFG=false should produce "note" level, not "warning"
        let results = vec![sample_pe_result()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        let cfg_result = sarif_results
            .iter()
            .find(|r| r["ruleId"] == "BHC104")
            .expect("CFG result should exist");
        assert_eq!(cfg_result["level"], "note", "CFG should be note level");
        assert!(
            cfg_result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("informational"),
            "CFG message should indicate informational"
        );
    }

    #[test]
    fn sarif_macho_code_signature_is_note_level() {
        // code_signature=false should produce "note" level, not "warning"
        let results = vec![sample_macho_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        let codesig = sarif_results
            .iter()
            .find(|r| r["ruleId"] == "BHC206")
            .expect("Code Signature result should exist");
        assert_eq!(
            codesig["level"], "note",
            "Code Signature should be note level"
        );
        // Other checks (e.g. PIE) should still be "warning"
        let pie = sarif_results
            .iter()
            .find(|r| r["ruleId"] == "BHC201")
            .expect("PIE result should exist");
        assert_eq!(pie["level"], "error", "PIE should be error level");
    }

    #[test]
    fn sarif_empty_results() {
        let results: Vec<CheckResult> = vec![];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(sarif_results.is_empty());
    }

    #[test]
    fn sarif_unsupported_format() {
        let results = vec![sample_unsupported_result()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(!sarif_results.is_empty());
        assert_eq!(sarif_results[0]["ruleId"], "BHC000");
    }

    #[test]
    fn sarif_deduplicates_rules_across_files() {
        // Two ELF files should not duplicate rule definitions
        let results = vec![sample_elf_result_all_fail(), sample_elf_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Check no duplicate rule IDs
        let mut ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Rules should not be duplicated");
    }

    // ---- collect_check_items ----

    #[test]
    fn collect_check_items_elf_count() {
        let result = sample_elf_result_all_pass();
        let items = collect_check_items(&result);
        // 9 existing (RELRO/Canary/NX/PIE/Fortify/RPATH/RUNPATH/Debug/Symtab)
        // + 1 F4 BHC013 Linkage. file_mode is None in the fixture so no BHC011 row.
        assert_eq!(items.len(), 10, "ELF should produce 10 check items");
    }

    #[test]
    fn collect_check_items_pe_count() {
        let result = sample_pe_result();
        let items = collect_check_items(&result);
        assert_eq!(items.len(), 7, "PE should produce 7 check items");
    }

    #[test]
    fn collect_check_items_unsupported_count() {
        let result = sample_unsupported_result();
        let items = collect_check_items(&result);
        assert_eq!(items.len(), 1, "Unsupported should produce 1 check item");
        assert!(!items[0].2, "Unsupported item should be a failure");
    }

    #[test]
    fn collect_check_items_elf_relro_full_passes() {
        let result = sample_elf_result_all_pass();
        let items = collect_check_items(&result);
        let relro = items.iter().find(|i| i.0 == "BHC001").unwrap();
        assert!(relro.2, "Full RELRO should pass");
    }

    #[test]
    fn collect_check_items_elf_relro_none_fails() {
        let result = sample_elf_result_all_fail();
        let items = collect_check_items(&result);
        let relro = items.iter().find(|i| i.0 == "BHC001").unwrap();
        assert!(!relro.2, "No RELRO should fail");
        assert_eq!(relro.3, "None");
    }

    #[test]
    fn collect_check_items_rpath_present_fails() {
        let result = sample_elf_result_all_fail();
        let items = collect_check_items(&result);
        let rpath = items.iter().find(|i| i.0 == "BHC006").unwrap();
        assert!(!rpath.2, "RPATH present should fail");
        assert_eq!(rpath.3, "/usr/local/lib");
    }

    #[test]
    fn collect_check_items_pe_cfg_is_warn_only() {
        let result = sample_pe_result();
        let items = collect_check_items(&result);
        let cfg = items.iter().find(|i| i.0 == "BHC104").unwrap();
        assert!(cfg.4, "CFG should be warn_only");
        let aslr = items.iter().find(|i| i.0 == "BHC101").unwrap();
        assert!(!aslr.4, "ASLR should not be warn_only");
    }

    #[test]
    fn collect_check_items_macho_code_signature_is_warn_only() {
        let result = sample_macho_result_all_fail();
        let items = collect_check_items(&result);
        let codesig = items.iter().find(|i| i.0 == "BHC206").unwrap();
        assert!(codesig.4, "Code Signature should be warn_only");
        let pie = items.iter().find(|i| i.0 == "BHC201").unwrap();
        assert!(!pie.4, "PIE should not be warn_only");
    }

    // ---- Mach-O table output ----

    #[test]
    fn table_output_contains_macho_properties() {
        let results = vec![sample_macho_result_all_pass()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("Mach-O"));
        assert!(output.contains("PIE"));
        assert!(output.contains("Stack Canary"));
        assert!(output.contains("ARC"));
        assert!(output.contains("NX Stack"));
        assert!(output.contains("NX Heap"));
        assert!(output.contains("Code Signature"));
        assert!(output.contains("Hardened Runtime"));
        assert!(output.contains("Restrict Segment"));
    }

    #[test]
    fn table_output_macho_details() {
        let results = vec![sample_macho_result_all_pass()];
        let output = format_results(&results, OutputFormat::Table);
        assert!(output.contains("MH_PIE"));
        assert!(output.contains("___stack_chk_fail/guard found"));
        assert!(output.contains("_objc_release found"));
        assert!(output.contains("LC_CODE_SIGNATURE present"));
        assert!(output.contains("CS_RUNTIME enabled"));
        assert!(output.contains("__RESTRICT,__restrict present"));
    }

    // ---- Mach-O JSON output ----

    #[test]
    fn json_output_macho_fields() {
        let results = vec![sample_macho_result_all_pass()];
        let output = format_results(&results, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let macho = &parsed["results"][0]["result"]["MachO"];
        assert_eq!(macho["pie"], true);
        assert_eq!(macho["stack_canary"], true);
        assert_eq!(macho["arc"], true);
        assert_eq!(macho["nx_stack"], true);
        assert_eq!(macho["nx_heap"], true);
        assert_eq!(macho["code_signature"], true);
        assert_eq!(macho["hardened_runtime"], true);
        assert_eq!(macho["restrict_segment"], true);
    }

    // ---- Mach-O SARIF output ----

    #[test]
    fn sarif_macho_no_failures_means_no_results() {
        let results = vec![sample_macho_result_all_pass()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(
            sarif_results.is_empty(),
            "All Mach-O checks pass, so no SARIF results"
        );
    }

    #[test]
    fn sarif_macho_failures_produce_results() {
        let results = vec![sample_macho_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let sarif_results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(
            !sarif_results.is_empty(),
            "Mach-O failures should produce SARIF results"
        );
    }

    #[test]
    fn sarif_macho_rule_ids() {
        let results = vec![sample_macho_result_all_fail()];
        let output = format_results(&results, OutputFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(rule_ids.contains(&"BHC201")); // PIE
        assert!(rule_ids.contains(&"BHC202")); // Stack Canary
        assert!(rule_ids.contains(&"BHC204")); // NX Stack
        assert!(rule_ids.contains(&"BHC206")); // Code Signature
    }

    // ---- Mach-O collect_check_items ----

    #[test]
    fn collect_check_items_macho_count() {
        let result = sample_macho_result_all_pass();
        let items = collect_check_items(&result);
        assert_eq!(items.len(), 8, "Mach-O should produce 8 check items");
    }
}
