//! F1 (BHC010): banned function detection.
//!
//! Walks `.dynsym` and (when present) `.symtab` looking for known dangerous C
//! library imports (`gets`, `strcpy`, `system`, …). Default list is hard-coded
//! from CWE-derived primary sources (see spec §F1); users can extend or
//! replace it via `--banned-functions` / `--banned-functions-replace`.
//!
//! `_chk` (FORTIFY_SOURCE) variants are tracked separately. When the binary
//! is linked against glibc *and* a fortified `__sprintf_chk` is present, a
//! plain `sprintf` import is suppressed because the compiler routed all calls
//! through the fortified wrapper. For musl / uclibc / bionic / unknown the
//! suppression is **not** applied (those libcs do not ship `_chk` variants);
//! this is the F5 fail-safe gate (spec §F1 L83-L90, §F5 L199).
//!
//! License posture (Ada §8): symbol list is curated from CWE / SEI CERT C
//! references. `checksec.sh` (Apache-2.0) and `pwntools` (MIT) are *not*
//! copied — both carry attribution requirements and bincheck stays free of
//! their lists by design.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use goblin::elf::Elf;
use serde::{Deserialize, Serialize};

use crate::libc_flavor::LibcFlavor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedFunction {
    pub name: String,
    pub severity: Severity,
}

/// Where in the ELF the banned symbol was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolSource {
    /// Found in `.dynsym` (dynamic import, typical for unstripped *and* stripped binaries).
    Dynsym,
    /// Found only in `.symtab` (unstripped static or partially-stripped binary).
    Symtab,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedDetection {
    pub function: BannedFunction,
    pub source: SymbolSource,
}

/// Default banned-function list. CWE-rooted; HIGH = unconditional buffer/command
/// hazards, MEDIUM = context-dependent (CWE-377 race, CWE-20 input parsing).
///
/// Sources: SEI CERT C (MSC24-C, STR07-C), CWE-242 / CWE-676 / CWE-377.
/// **Not** copied from `checksec.sh` / `pwntools` (license-restricted lists).
pub fn default_list() -> Vec<BannedFunction> {
    use Severity::*;
    [
        ("gets", High),    // CWE-242 (always unsafe)
        ("strcpy", High),  // CWE-120 buffer overflow
        ("strcat", High),  // CWE-120
        ("sprintf", High), // CWE-120
        ("vsprintf", High),
        ("system", High), // CWE-78 / CWE-676
        ("popen", High),  // CWE-78
        ("scanf", Medium),
        ("tmpnam", Medium), // CWE-377
        ("mktemp", Medium), // CWE-377
    ]
    .into_iter()
    .map(|(n, s)| BannedFunction {
        name: n.to_string(),
        severity: s,
    })
    .collect()
}

/// Mapping of fortified `_chk` variant → original symbol it covers.
/// Used by the glibc fortify-suppression gate.
fn chk_variant_map() -> &'static [(&'static str, &'static str)] {
    &[
        ("__sprintf_chk", "sprintf"),
        ("__strcpy_chk", "strcpy"),
        ("__strcat_chk", "strcat"),
        ("__snprintf_chk", "snprintf"),
        ("__vsprintf_chk", "vsprintf"),
        ("__memcpy_chk", "memcpy"),
        ("__stpcpy_chk", "stpcpy"),
    ]
}

/// Load a banned-function overlay from a JSON file. Format:
/// `[{"name": "foo", "severity": "HIGH"}, ...]`.
pub fn load_from_json(path: &Path) -> Result<Vec<BannedFunction>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let parsed: Vec<BannedFunction> =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    Ok(parsed)
}

/// Merge an overlay onto the default list. Same-name entries from `overlay`
/// override the corresponding `default` entry; new names are appended.
pub fn merge(default: Vec<BannedFunction>, overlay: Vec<BannedFunction>) -> Vec<BannedFunction> {
    // Preserve insertion order of `default` while letting overlay override.
    let mut by_name: BTreeMap<String, BannedFunction> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for entry in default {
        order.push(entry.name.clone());
        by_name.insert(entry.name.clone(), entry);
    }
    for entry in overlay {
        if !by_name.contains_key(&entry.name) {
            order.push(entry.name.clone());
        }
        by_name.insert(entry.name.clone(), entry);
    }
    order
        .into_iter()
        .filter_map(|n| by_name.remove(&n))
        .collect()
}

/// Run F1 detection. `libc` is consulted only to gate fortify suppression
/// (`Glibc` enables it; everything else leaves bare imports visible).
pub fn check(elf: &Elf, list: &[BannedFunction], libc: LibcFlavor) -> Vec<BannedDetection> {
    // Track all observed symbol names across dynsym + symtab and the source
    // they came from. Dynsym wins ties (it is the import that actually links
    // at runtime).
    let mut seen: HashMap<String, SymbolSource> = HashMap::new();

    // goblin's strtab returns `Option<&str>`; non-UTF-8 bytes already fall
    // through to `None` (goblin uses `from_utf8` internally), satisfying the
    // spec's "CString 経由で UTF-8 検証、不正シンボルは skip" requirement.
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            && !name.is_empty()
        {
            seen.entry(name.to_string()).or_insert(SymbolSource::Dynsym);
        }
    }
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && !name.is_empty()
        {
            seen.entry(name.to_string()).or_insert(SymbolSource::Symtab);
        }
    }

    // Fortify suppression: only when libc == Glibc, suppress the original of
    // any `_chk` variant we observed. PLT-resident bare imports still count
    // (they live in dynsym), so we only suppress when the bare symbol is
    // *not* present in dynsym.
    let mut suppressed: HashSet<&str> = HashSet::new();
    if libc == LibcFlavor::Glibc {
        for (chk, original) in chk_variant_map() {
            if seen.contains_key(*chk) {
                // Per spec L84: "PLT に裸の sprintf が残っていたら検出"
                // → suppress only when the bare symbol is absent from dynsym.
                let present_in_dynsym = matches!(seen.get(*original), Some(SymbolSource::Dynsym));
                if !present_in_dynsym {
                    suppressed.insert(*original);
                }
            }
        }
    }

    let mut detections: Vec<BannedDetection> = Vec::new();
    // Iterate in `list` order so output is deterministic and matches user
    // expectations (HIGH-then-MEDIUM in the default list).
    for entry in list {
        if suppressed.contains(entry.name.as_str()) {
            continue;
        }
        let Some(source) = seen.get(entry.name.as_str()) else {
            continue;
        };
        detections.push(BannedDetection {
            function: entry.clone(),
            source: *source,
        });
    }

    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_contains_high_severity_classics() {
        let list = default_list();
        let names: Vec<&str> = list.iter().map(|b| b.name.as_str()).collect();
        for required in [
            "gets", "strcpy", "strcat", "sprintf", "vsprintf", "system", "popen",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
        for entry in &list {
            if matches!(
                entry.name.as_str(),
                "gets" | "strcpy" | "strcat" | "sprintf" | "vsprintf" | "system" | "popen"
            ) {
                assert_eq!(
                    entry.severity,
                    Severity::High,
                    "{} should be HIGH",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn default_list_medium_severity_set() {
        let list = default_list();
        for entry in &list {
            if matches!(entry.name.as_str(), "scanf" | "tmpnam" | "mktemp") {
                assert_eq!(
                    entry.severity,
                    Severity::Medium,
                    "{} should be MEDIUM",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn severity_serializes_uppercase() {
        let json = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(json, "\"HIGH\"");
        let json = serde_json::to_string(&Severity::Medium).unwrap();
        assert_eq!(json, "\"MEDIUM\"");
    }

    #[test]
    fn merge_overlay_overrides_severity() {
        let default = vec![
            BannedFunction {
                name: "strcpy".into(),
                severity: Severity::High,
            },
            BannedFunction {
                name: "scanf".into(),
                severity: Severity::Medium,
            },
        ];
        let overlay = vec![BannedFunction {
            name: "scanf".into(),
            severity: Severity::Low,
        }];
        let merged = merge(default, overlay);
        let scanf = merged.iter().find(|e| e.name == "scanf").unwrap();
        assert_eq!(scanf.severity, Severity::Low);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_overlay_appends_new_names() {
        let default = vec![BannedFunction {
            name: "strcpy".into(),
            severity: Severity::High,
        }];
        let overlay = vec![BannedFunction {
            name: "newfn".into(),
            severity: Severity::Low,
        }];
        let merged = merge(default, overlay);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].name, "newfn");
    }

    #[test]
    fn chk_variant_map_covers_spec_seven() {
        // Spec L82: seven _chk variants must be recognised.
        let names: Vec<&str> = chk_variant_map().iter().map(|(c, _)| *c).collect();
        for required in [
            "__sprintf_chk",
            "__strcpy_chk",
            "__strcat_chk",
            "__snprintf_chk",
            "__vsprintf_chk",
            "__memcpy_chk",
            "__stpcpy_chk",
        ] {
            assert!(
                names.contains(&required),
                "missing _chk variant: {required}"
            );
        }
    }

    #[test]
    fn load_from_json_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_banned_test.json");
        let payload = r#"[{"name":"strcpy","severity":"HIGH"},{"name":"foo","severity":"LOW"}]"#;
        fs::write(&path, payload).unwrap();
        let loaded = load_from_json(&path).expect("should parse");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "strcpy");
        assert_eq!(loaded[1].severity, Severity::Low);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_from_json_invalid_returns_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_banned_invalid.json");
        fs::write(&path, "not json").unwrap();
        let err = load_from_json(&path).unwrap_err();
        assert!(err.contains("parse"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_from_json_missing_file_returns_error() {
        let err = load_from_json(Path::new("/nonexistent/banned.json")).unwrap_err();
        assert!(err.contains("read"));
    }

    // Synthetic check() tests using a parseable but symbol-free ELF would
    // need a hand-rolled fixture; those live under tests/banned_function_detection.rs.
    // The unit tests above exercise the pure-data paths (default list,
    // merge semantics, JSON loader, _chk map) which is where most regressions
    // historically lurked.
}
