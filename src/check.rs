use std::fs;
use std::io;

use goblin::Object;
use serde::Serialize;

use crate::elf::{ElfCheckResult, check_elf};
use crate::macho::{MachoCheckResult, check_macho};
use crate::pe::{PeCheckResult, check_pe};

/// Unified check result for any binary format
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub file_path: String,
    pub format: BinaryFormat,
    pub result: FormatResult,
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
    let bytes = fs::read(path)?;

    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let result = check_elf(&elf);
            Ok(CheckResult {
                file_path: path.to_string(),
                format: BinaryFormat::Elf,
                result: FormatResult::Elf(result),
            })
        }
        Ok(Object::PE(pe)) => {
            let result = check_pe(&pe);
            Ok(CheckResult {
                file_path: path.to_string(),
                format: BinaryFormat::Pe,
                result: FormatResult::Pe(result),
            })
        }
        Ok(Object::Mach(_)) => {
            // Re-parse from raw bytes for detailed security checks
            match check_macho(&bytes) {
                Some(result) => Ok(CheckResult {
                    file_path: path.to_string(),
                    format: BinaryFormat::MachO,
                    result: FormatResult::MachO(result),
                }),
                None => Ok(CheckResult {
                    file_path: path.to_string(),
                    format: BinaryFormat::MachO,
                    result: FormatResult::Unsupported,
                }),
            }
        }
        Ok(Object::Archive(_) | Object::Unknown(_)) | Ok(_) => Ok(CheckResult {
            file_path: path.to_string(),
            format: BinaryFormat::Unknown,
            result: FormatResult::Unsupported,
        }),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
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
            rpath: None,
            runpath: None,
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
        };
        assert!(result.has_failures());
    }

    #[test]
    fn check_result_pe_delegates() {
        use crate::pe::{PeCheckResult, PeDebugInfo};
        let pe_result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: true,
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
                rpath: None,
                runpath: None,
                debug_info: ElfDebugInfo {
                    dwarf_sections: vec![],
                    has_symtab: false,
                    has_strtab: false,
                    build_id: None,
                },
            }),
        };
        let json = serde_json::to_string(&result).expect("should serialize");
        assert!(json.contains("\"file_path\":\"test.elf\""));
        assert!(json.contains("\"relro\":\"Full\""));
    }
}
