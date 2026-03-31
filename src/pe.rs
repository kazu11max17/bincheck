use goblin::pe::PE;
use serde::Serialize;

// PE DLL Characteristics flags
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

/// Debug information found in a PE binary
#[derive(Debug, Clone, Serialize)]
pub struct PeDebugInfo {
    /// Whether a debug directory entry is present
    pub has_debug_directory: bool,
    /// PDB path if found in CodeView debug data
    pub pdb_path: Option<String>,
}

impl PeDebugInfo {
    /// Returns true if any debug information is present
    pub fn has_debug_info(&self) -> bool {
        self.has_debug_directory
    }
}

/// Result of all PE security checks
#[derive(Debug, Clone, Serialize)]
pub struct PeCheckResult {
    pub aslr: bool,
    pub high_entropy_aslr: bool,
    pub dep_nx: bool,
    pub cfg: bool,
    pub safe_seh: bool,
    pub authenticode: bool,
    pub debug_info: PeDebugInfo,
}

impl PeCheckResult {
    /// Returns true if any security check is in a failing state
    pub fn has_failures(&self) -> bool {
        !self.aslr || !self.dep_nx || !self.safe_seh
    }
}

/// Run all security checks on a PE binary
pub fn check_pe(pe: &PE) -> PeCheckResult {
    let dll_characteristics = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let aslr = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    let high_entropy_aslr = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    let dep_nx = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    let cfg = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    // SafeSEH: NO_SEH flag means SEH is disabled entirely (not SafeSEH)
    // If NO_SEH is set, SafeSEH is effectively not applicable / disabled
    let no_seh = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0;
    let safe_seh = !no_seh;

    // Authenticode: check for security data directory entry (Certificate Table)
    let authenticode = pe
        .header
        .optional_header
        .and_then(|oh| {
            let dirs = oh.data_directories;
            dirs.get_certificate_table().map(|ct| ct.size > 0)
        })
        .unwrap_or(false);

    // Debug directory: check for IMAGE_DIRECTORY_ENTRY_DEBUG (index 6)
    let debug_dir = pe
        .header
        .optional_header
        .and_then(|oh| {
            let dirs = oh.data_directories;
            // Debug directory is at index 6
            dirs.get_debug_table().map(|dt| dt.size > 0)
        })
        .unwrap_or(false);

    // Try to extract PDB path from debug info
    let pdb_path = if let Some(ref debug_data) = pe.debug_data {
        debug_data
            .codeview_pdb70_debug_info
            .as_ref()
            .and_then(|cv| {
                std::str::from_utf8(cv.filename)
                    .ok()
                    .map(|s| s.trim_end_matches('\0').to_string())
            })
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let debug_info = PeDebugInfo {
        has_debug_directory: debug_dir,
        pdb_path,
    };

    PeCheckResult {
        aslr,
        high_entropy_aslr,
        dep_nx,
        cfg,
        safe_seh,
        authenticode,
        debug_info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_pe_debug_info() -> PeDebugInfo {
        PeDebugInfo {
            has_debug_directory: false,
            pdb_path: None,
        }
    }

    // ---- PeDebugInfo ----

    #[test]
    fn pe_debug_info_has_debug_with_directory() {
        let info = PeDebugInfo {
            has_debug_directory: true,
            pdb_path: None,
        };
        assert!(info.has_debug_info());
    }

    #[test]
    fn pe_debug_info_no_debug_clean() {
        let info = no_pe_debug_info();
        assert!(!info.has_debug_info());
    }

    #[test]
    fn pe_debug_info_with_pdb_path() {
        let info = PeDebugInfo {
            has_debug_directory: true,
            pdb_path: Some("C:\\build\\app.pdb".to_string()),
        };
        assert!(info.has_debug_info());
        assert_eq!(info.pdb_path.as_deref(), Some("C:\\build\\app.pdb"));
    }

    // ---- PeCheckResult::has_failures ----

    #[test]
    fn has_failures_all_enabled() {
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: true,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn has_failures_no_aslr() {
        let result = PeCheckResult {
            aslr: false,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: true,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_dep() {
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: false,
            cfg: true,
            safe_seh: true,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_cfg_not_checked() {
        // cfg=false alone should NOT cause has_failures (warn-only, not available on MinGW/older MSVC)
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: false,
            safe_seh: true,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "CFG is not in the has_failures check"
        );
    }

    #[test]
    fn has_failures_no_safe_seh() {
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: false,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_authenticode_not_checked() {
        // authenticode=false alone should NOT cause has_failures to return true
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: true,
            dep_nx: true,
            cfg: true,
            safe_seh: true,
            authenticode: false,
            debug_info: no_pe_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "authenticode is not in the has_failures check"
        );
    }

    #[test]
    fn has_failures_high_entropy_aslr_not_checked() {
        // high_entropy_aslr=false alone should NOT cause has_failures to return true
        let result = PeCheckResult {
            aslr: true,
            high_entropy_aslr: false,
            dep_nx: true,
            cfg: true,
            safe_seh: true,
            authenticode: true,
            debug_info: no_pe_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "high_entropy_aslr is not in the has_failures check"
        );
    }

    #[test]
    fn has_failures_multiple_failures() {
        let result = PeCheckResult {
            aslr: false,
            high_entropy_aslr: false,
            dep_nx: false,
            cfg: false,
            safe_seh: false,
            authenticode: false,
            debug_info: no_pe_debug_info(),
        };
        assert!(result.has_failures());
    }

    // ---- PE flag constants ----

    #[test]
    fn pe_flag_constants_correct() {
        assert_eq!(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, 0x0020);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, 0x0040);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, 0x0100);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_NO_SEH, 0x0400);
        assert_eq!(IMAGE_DLLCHARACTERISTICS_GUARD_CF, 0x4000);
    }

    // ---- PE binary parsing tests using minimal PE headers ----

    /// Build a minimal PE32+ (64-bit) binary with specified DLL characteristics
    fn minimal_pe(dll_characteristics: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 512];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew: PE header offset at 0x80
        buf[0x3C] = 0x80;

        let pe_off = 0x80usize;
        // PE signature "PE\0\0"
        buf[pe_off] = b'P';
        buf[pe_off + 1] = b'E';

        // COFF header (20 bytes starting at pe_off + 4)
        let coff_off = pe_off + 4;
        // Machine = AMD64 (0x8664)
        buf[coff_off] = 0x64;
        buf[coff_off + 1] = 0x86;
        // NumberOfSections = 0
        buf[coff_off + 2] = 0;
        // SizeOfOptionalHeader = 240 (0xF0) for PE32+
        buf[coff_off + 16] = 0xF0;
        buf[coff_off + 17] = 0x00;

        // Optional header starts at coff_off + 20
        let opt_off = coff_off + 20;
        // Magic = PE32+ (0x020B)
        buf[opt_off] = 0x0B;
        buf[opt_off + 1] = 0x02;

        // DllCharacteristics is at offset 70 in the optional header for PE32+
        let dll_char_off = opt_off + 70;
        buf[dll_char_off] = (dll_characteristics & 0xFF) as u8;
        buf[dll_char_off + 1] = ((dll_characteristics >> 8) & 0xFF) as u8;

        // NumberOfRvaAndSizes at offset 108 in optional header for PE32+
        let num_rva_off = opt_off + 108;
        buf[num_rva_off] = 16; // 16 data directories

        buf
    }

    #[test]
    fn pe_all_hardening_flags_set() {
        let flags = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        let bytes = minimal_pe(flags);

        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&bytes) {
            let result = check_pe(&pe);
            assert!(result.aslr, "DYNAMIC_BASE should enable ASLR");
            assert!(
                result.high_entropy_aslr,
                "HIGH_ENTROPY_VA should enable high entropy ASLR"
            );
            assert!(result.dep_nx, "NX_COMPAT should enable DEP");
            assert!(result.cfg, "GUARD_CF should enable CFG");
            // NO_SEH is not set, so safe_seh should be true
            assert!(
                result.safe_seh,
                "SafeSEH should be true when NO_SEH is not set"
            );
            assert!(
                !result.authenticode,
                "No certificate table means no authenticode"
            );
        } else {
            panic!("Failed to parse minimal PE binary");
        }
    }

    #[test]
    fn pe_no_hardening_flags() {
        let bytes = minimal_pe(0);
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&bytes) {
            let result = check_pe(&pe);
            assert!(!result.aslr);
            assert!(!result.high_entropy_aslr);
            assert!(!result.dep_nx);
            assert!(!result.cfg);
            assert!(result.safe_seh, "Without NO_SEH, safe_seh is true");
            assert!(!result.authenticode);
        } else {
            panic!("Failed to parse minimal PE binary");
        }
    }

    #[test]
    fn pe_no_seh_flag_disables_safe_seh() {
        let bytes = minimal_pe(IMAGE_DLLCHARACTERISTICS_NO_SEH);
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&bytes) {
            let result = check_pe(&pe);
            assert!(!result.safe_seh, "NO_SEH flag should disable SafeSEH");
        } else {
            panic!("Failed to parse minimal PE binary");
        }
    }

    #[test]
    fn pe_aslr_only() {
        let bytes = minimal_pe(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&bytes) {
            let result = check_pe(&pe);
            assert!(result.aslr);
            assert!(!result.high_entropy_aslr);
            assert!(!result.dep_nx);
            assert!(!result.cfg);
        } else {
            panic!("Failed to parse minimal PE binary");
        }
    }
}
