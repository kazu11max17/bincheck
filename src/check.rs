use std::fs;
use std::io;

use goblin::Object;
use serde::Serialize;

use crate::elf::{ElfCheckResult, check_elf};
use crate::macho::{MachoCheckResult, check_macho};
use crate::pe::{PeCheckResult, check_pe};

/// F2 (BHC011): file-level SUID/SGID/symlink classification.
///
/// `NotApplicable` is reported on non-Unix targets; the rest are observed via
/// `std::fs::symlink_metadata` (deliberately *not* following symlinks so the bit
/// reflects the file the user passed on the CLI, not the target).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileModeStatus {
    /// Regular file, no SUID or SGID set.
    Normal,
    /// SUID bit (04000) is set.
    Suid,
    /// SGID bit (02000) is set.
    Sgid,
    /// Both SUID and SGID are set.
    SuidSgid,
    /// The path itself is a symlink (informational; the binary check still runs
    /// against the resolved target via `fs::read`).
    Symlink,
    /// Platform does not expose Unix mode bits (e.g. Windows).
    NotApplicable,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMode {
    pub status: FileModeStatus,
    /// Convenience flags. `false` on `NotApplicable` / `Symlink`.
    pub suid: bool,
    pub sgid: bool,
}

impl FileMode {
    /// True when SUID or SGID is set. SUID/SGID is treated as a *warning* by
    /// default; it only flips a run to exit-1 when `--strict` is passed.
    pub fn is_warning(&self) -> bool {
        matches!(
            self.status,
            FileModeStatus::Suid | FileModeStatus::Sgid | FileModeStatus::SuidSgid
        )
    }
}

#[cfg(unix)]
fn detect_file_mode(path: &str) -> FileMode {
    use std::os::unix::fs::MetadataExt;

    // symlink_metadata: do NOT follow the symlink. We want the bit on the entry the user named.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return FileMode {
                status: FileModeStatus::Normal,
                suid: false,
                sgid: false,
            };
        }
    };

    if meta.file_type().is_symlink() {
        return FileMode {
            status: FileModeStatus::Symlink,
            suid: false,
            sgid: false,
        };
    }

    let mode = meta.mode();
    let suid = (mode & 0o4000) != 0;
    let sgid = (mode & 0o2000) != 0;
    let status = match (suid, sgid) {
        (true, true) => FileModeStatus::SuidSgid,
        (true, false) => FileModeStatus::Suid,
        (false, true) => FileModeStatus::Sgid,
        (false, false) => FileModeStatus::Normal,
    };
    FileMode { status, suid, sgid }
}

#[cfg(not(unix))]
fn detect_file_mode(_path: &str) -> FileMode {
    FileMode {
        status: FileModeStatus::NotApplicable,
        suid: false,
        sgid: false,
    }
}

/// Unified check result for any binary format
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub file_path: String,
    pub format: BinaryFormat,
    pub result: FormatResult,
    /// F2 (BHC011): SUID/SGID/symlink mode of `file_path`.
    /// Populated by `check_file`; absent when the result is constructed in tests
    /// or by other entry points that bypass `check_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<FileMode>,
}

impl CheckResult {
    pub fn has_failures(&self) -> bool {
        match &self.result {
            FormatResult::Elf(r) => r.has_failures(),
            FormatResult::Pe(r) => r.has_failures(),
            FormatResult::MachO(r) => r.has_failures(),
            FormatResult::Unsupported => true,
        }
    }

    /// True when at least one check is in a *warn* (not error) state.
    /// Currently this is only F2 SUID/SGID detection; consumers wire this into
    /// `--strict` so warnings become exit-1.
    pub fn has_warnings(&self) -> bool {
        self.file_mode.as_ref().is_some_and(|m| m.is_warning())
    }
}

/// Detected binary format
#[derive(Debug, Clone, Serialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Format-specific check results
#[derive(Debug, Clone, Serialize)]
pub enum FormatResult {
    Elf(ElfCheckResult),
    Pe(PeCheckResult),
    MachO(MachoCheckResult),
    Unsupported,
}

/// Check a binary file for security properties
pub fn check_file(path: &str) -> Result<CheckResult, io::Error> {
    // F2: capture mode bits *before* fs::read follows the symlink. We still
    // call fs::read afterwards so the binary content check runs against the
    // resolved target — symlink_metadata only tells us about the entry itself.
    let file_mode = Some(detect_file_mode(path));

    let bytes = fs::read(path)?;

    let (format, result) = match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => (BinaryFormat::Elf, FormatResult::Elf(check_elf(&elf))),
        Ok(Object::PE(pe)) => (BinaryFormat::Pe, FormatResult::Pe(check_pe(&pe))),
        Ok(Object::Mach(_)) => match check_macho(&bytes) {
            Some(r) => (BinaryFormat::MachO, FormatResult::MachO(r)),
            None => (BinaryFormat::MachO, FormatResult::Unsupported),
        },
        Ok(Object::Archive(_) | Object::Unknown(_)) | Ok(_) => {
            (BinaryFormat::Unknown, FormatResult::Unsupported)
        }
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    };

    Ok(CheckResult {
        file_path: path.to_string(),
        format,
        result,
        file_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- BinaryFormat display ----

    #[test]
    fn binary_format_display() {
        assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
        assert_eq!(BinaryFormat::Pe.to_string(), "PE");
        assert_eq!(BinaryFormat::MachO.to_string(), "Mach-O");
        assert_eq!(BinaryFormat::Unknown.to_string(), "Unknown");
    }

    // ---- CheckResult::has_failures ----

    #[test]
    fn check_result_unsupported_always_fails() {
        let result = CheckResult {
            file_path: "test.bin".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: None,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn check_result_elf_delegates() {
        use crate::elf::{ElfCheckResult, ElfDebugInfo, RelroStatus};
        let elf_result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
            debug_info: ElfDebugInfo {
                dwarf_sections: vec![],
                has_symtab: false,
                has_strtab: false,
                build_id: None,
            },
        };
        let result = CheckResult {
            file_path: "test.elf".to_string(),
            format: BinaryFormat::Elf,
            result: FormatResult::Elf(elf_result),
            file_mode: None,
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn check_result_macho_delegates() {
        use crate::macho::MachoCheckResult;
        let macho_result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: false,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: false,
            restrict_segment: false,
        };
        let result = CheckResult {
            file_path: "test.macho".to_string(),
            format: BinaryFormat::MachO,
            result: FormatResult::MachO(macho_result),
            file_mode: None,
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn check_result_macho_has_failures() {
        use crate::macho::MachoCheckResult;
        let macho_result = MachoCheckResult {
            pie: false,
            stack_canary: true,
            arc: false,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: false,
            restrict_segment: false,
        };
        let result = CheckResult {
            file_path: "test.macho".to_string(),
            format: BinaryFormat::MachO,
            result: FormatResult::MachO(macho_result),
            file_mode: None,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn check_result_pe_delegates() {
        use crate::pe::{PeCheckResult, PeDebugInfo, SafeSehStatus};
        let pe_result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: SafeSehStatus::Enabled,
            authenticode: false,
            debug_info: PeDebugInfo {
                has_debug_directory: false,
                pdb_path: None,
            },
        };
        let result = CheckResult {
            file_path: "test.exe".to_string(),
            format: BinaryFormat::Pe,
            result: FormatResult::Pe(pe_result),
            file_mode: None,
        };
        assert!(!result.has_failures());
    }

    // ---- check_file error handling ----

    #[test]
    fn check_file_nonexistent() {
        let err = check_file("/nonexistent/path/binary").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn check_file_invalid_binary() {
        // Create a temp file with garbage data
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_invalid.bin");
        fs::write(&path, b"this is not a binary").unwrap();

        let result = check_file(path.to_str().unwrap());
        // goblin may parse it as Unknown or return an error
        match result {
            Ok(r) => {
                // If parsed successfully, it should be Unknown/Unsupported
                assert!(matches!(r.format, BinaryFormat::Unknown));
                assert!(matches!(r.result, FormatResult::Unsupported));
            }
            Err(_) => {
                // Also acceptable - invalid data error
            }
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn check_file_empty() {
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_empty.bin");
        fs::write(&path, b"").unwrap();

        let result = check_file(path.to_str().unwrap());
        // Empty file should either error or be classified as Unknown
        match result {
            Ok(r) => {
                assert!(matches!(r.format, BinaryFormat::Unknown));
            }
            Err(_) => {
                // Also acceptable
            }
        }

        let _ = fs::remove_file(&path);
    }

    // ---- F2 (BHC011): file_mode detection ----

    #[test]
    #[cfg(unix)]
    fn file_mode_normal_for_regular_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_f2_normal.bin");
        fs::write(&path, b"\x7fELF\x02\x01\x01\x00").unwrap();

        let mode = detect_file_mode(path.to_str().unwrap());
        assert_eq!(mode.status, FileModeStatus::Normal);
        assert!(!mode.suid);
        assert!(!mode.sgid);
        assert!(!mode.is_warning());

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_suid_detected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_f2_suid.bin");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();

        let mode = detect_file_mode(path.to_str().unwrap());
        assert_eq!(mode.status, FileModeStatus::Suid);
        assert!(mode.suid);
        assert!(!mode.sgid);
        assert!(mode.is_warning());

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_sgid_detected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_f2_sgid.bin");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o2755)).unwrap();

        let mode = detect_file_mode(path.to_str().unwrap());
        assert_eq!(mode.status, FileModeStatus::Sgid);
        assert!(!mode.suid);
        assert!(mode.sgid);
        assert!(mode.is_warning());

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_suid_sgid_both_detected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join("bincheck_test_f2_both.bin");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o6755)).unwrap();

        let mode = detect_file_mode(path.to_str().unwrap());
        assert_eq!(mode.status, FileModeStatus::SuidSgid);
        assert!(mode.suid);
        assert!(mode.sgid);
        assert!(mode.is_warning());

        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_symlink_does_not_follow() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = std::env::temp_dir();
        let target = dir.join("bincheck_test_f2_symlink_target.bin");
        let link = dir.join("bincheck_test_f2_symlink.bin");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);

        fs::write(&target, b"x").unwrap();
        // Set SUID on the *target*. If we accidentally followed, we'd see Suid.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o4755)).unwrap();
        symlink(&target, &link).unwrap();

        let mode = detect_file_mode(link.to_str().unwrap());
        assert_eq!(
            mode.status,
            FileModeStatus::Symlink,
            "must report symlink, not follow to suid target"
        );
        assert!(!mode.is_warning());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn check_result_has_warnings_only_on_suid_sgid() {
        // Regular file → no warning
        let r = CheckResult {
            file_path: "x".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: Some(FileMode {
                status: FileModeStatus::Normal,
                suid: false,
                sgid: false,
            }),
        };
        assert!(!r.has_warnings());

        // SUID set → warning
        let r2 = CheckResult {
            file_path: "x".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: Some(FileMode {
                status: FileModeStatus::Suid,
                suid: true,
                sgid: false,
            }),
        };
        assert!(r2.has_warnings());

        // No file_mode → no warning
        let r3 = CheckResult {
            file_path: "x".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: None,
        };
        assert!(!r3.has_warnings());
    }

    #[test]
    fn file_mode_serializes_snake_case() {
        let m = FileMode {
            status: FileModeStatus::SuidSgid,
            suid: true,
            sgid: true,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"status\":\"suid_sgid\""));
    }

    #[test]
    fn file_mode_field_omitted_when_none() {
        let r = CheckResult {
            file_path: "x".to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
            file_mode: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"file_mode\""), "got: {}", json);
    }

    #[test]
    #[cfg(not(unix))]
    fn file_mode_not_applicable_on_non_unix() {
        let mode = detect_file_mode("anything");
        assert_eq!(mode.status, FileModeStatus::NotApplicable);
        assert!(!mode.is_warning());
    }

    // ---- check_file with real system binaries (Linux only) ----

    #[test]
    #[cfg(target_os = "linux")]
    fn check_file_system_binary() {
        // /bin/ls should exist on any Linux system
        if let Ok(result) = check_file("/bin/ls") {
            assert_eq!(result.file_path, "/bin/ls");
            assert!(matches!(result.format, BinaryFormat::Elf));
            assert!(matches!(result.result, FormatResult::Elf(_)));
        }
    }

    // ---- Serialization ----

    #[test]
    fn check_result_serializes_to_json() {
        use crate::elf::{ElfCheckResult, ElfDebugInfo, RelroStatus};
        let result = CheckResult {
            file_path: "test.elf".to_string(),
            format: BinaryFormat::Elf,
            result: FormatResult::Elf(ElfCheckResult {
                relro: RelroStatus::Full,
                stack_canary: true,
                nx: true,
                pie: true,
                fortify_source: false,
                fortified_functions: vec![],
                fortify_level: None,
                rpath: None,
                runpath: None,
                linkage: None,
                df_1_pie: false,
                debug_info: ElfDebugInfo {
                    dwarf_sections: vec![],
                    has_symtab: false,
                    has_strtab: false,
                    build_id: None,
                },
            }),
            file_mode: None,
        };
        let json = serde_json::to_string(&result).expect("should serialize");
        assert!(json.contains("\"file_path\":\"test.elf\""));
        assert!(json.contains("\"relro\":\"Full\""));
    }
}
