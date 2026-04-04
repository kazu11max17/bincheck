use goblin::elf::Elf;
use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_RPATH, DT_RUNPATH};
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};
use serde::Serialize;

/// RELRO protection level
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum RelroStatus {
    Full,
    Partial,
    None,
}

impl std::fmt::Display for RelroStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelroStatus::Full => write!(f, "Full"),
            RelroStatus::Partial => write!(f, "Partial"),
            RelroStatus::None => write!(f, "None"),
        }
    }
}

/// Debug information found in an ELF binary
#[derive(Debug, Clone, Serialize)]
pub struct ElfDebugInfo {
    /// DWARF debug sections found (e.g. .debug_info, .debug_abbrev, etc.)
    pub dwarf_sections: Vec<String>,
    /// Whether .symtab is present (unstripped binary)
    pub has_symtab: bool,
    /// Whether .strtab is present
    pub has_strtab: bool,
    /// Build ID from .note.gnu.build-id (informational)
    pub build_id: Option<String>,
}

impl ElfDebugInfo {
    /// Returns true if any debug/symbol information is present
    pub fn has_debug_info(&self) -> bool {
        !self.dwarf_sections.is_empty() || self.has_symtab
    }
}

/// Result of all ELF security checks
#[derive(Debug, Clone, Serialize)]
pub struct ElfCheckResult {
    pub relro: RelroStatus,
    pub stack_canary: bool,
    pub nx: bool,
    pub pie: bool,
    pub fortify_source: bool,
    pub fortified_functions: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub debug_info: ElfDebugInfo,
}

impl ElfCheckResult {
    /// Returns true if any security check is in a failing state
    pub fn has_failures(&self) -> bool {
        self.relro == RelroStatus::None
            || !self.stack_canary
            || !self.nx
            || !self.pie
            || self.rpath.is_some()
            || self.runpath.is_some()
    }
}

/// Check RELRO status of an ELF binary
fn check_relro(elf: &Elf) -> RelroStatus {
    let has_relro_segment = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);

    if !has_relro_segment {
        return RelroStatus::None;
    }

    // Check for BIND_NOW in dynamic entries
    let has_bind_now = if let Some(ref dynamic) = elf.dynamic {
        dynamic.dyns.iter().any(|d| {
            // DF_BIND_NOW in DT_FLAGS
            (d.d_tag == goblin::elf::dynamic::DT_FLAGS && (d.d_val & DF_BIND_NOW) != 0)
            // DF_1_NOW in DT_FLAGS_1
            || (d.d_tag == goblin::elf::dynamic::DT_FLAGS_1 && (d.d_val & DF_1_NOW) != 0)
        })
    } else {
        false
    };

    if has_bind_now {
        RelroStatus::Full
    } else {
        RelroStatus::Partial
    }
}

/// Check for stack canary (__stack_chk_fail in dynamic or static symbols)
///
/// Dynamically linked binaries have __stack_chk_fail in dynsyms.
/// Statically linked binaries (common in embedded) only have it in symtab.
fn check_stack_canary(elf: &Elf) -> bool {
    let in_dynsyms = elf.dynsyms.iter().any(|sym| {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            name == "__stack_chk_fail"
        } else {
            false
        }
    });
    if in_dynsyms {
        return true;
    }
    elf.syms.iter().any(|sym| {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            name == "__stack_chk_fail"
        } else {
            false
        }
    })
}

/// Check NX (No-Execute stack): PT_GNU_STACK without PF_X
fn check_nx(elf: &Elf) -> bool {
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            // NX is enabled if the stack segment does NOT have execute permission
            return (ph.p_flags & PF_X) == 0;
        }
    }
    // If no GNU_STACK segment, assume NX is not explicitly set (conservative)
    false
}

/// Check if binary is Position Independent Executable
fn check_pie(elf: &Elf) -> bool {
    // ET_DYN (3) = shared object / PIE
    // ET_EXEC (2) = fixed address executable
    elf.header.e_type == goblin::elf::header::ET_DYN
}

/// Check for fortified functions (__*_chk pattern in dynamic symbols)
fn check_fortify(elf: &Elf) -> (bool, Vec<String>) {
    let mut fortified = Vec::new();

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            && name.ends_with("_chk")
            && name.starts_with("__")
        {
            fortified.push(name.to_string());
        }
    }

    let has_fortify = !fortified.is_empty();
    (has_fortify, fortified)
}

/// DWARF section names to look for
const DWARF_SECTIONS: &[&str] = &[
    ".debug_info",
    ".debug_abbrev",
    ".debug_line",
    ".debug_str",
    ".debug_ranges",
    ".debug_aranges",
    ".debug_loc",
    ".debug_frame",
    ".debug_macinfo",
    ".debug_types",
    ".debug_pubtypes",
    ".debug_pubnames",
    ".debug_line_str",
    ".debug_loclists",
    ".debug_rnglists",
    ".debug_str_offsets",
    ".debug_addr",
];

/// Check for debug information in ELF section headers
fn check_debug_info(elf: &Elf) -> ElfDebugInfo {
    let mut dwarf_sections = Vec::new();
    let mut has_symtab = false;
    let mut has_strtab = false;
    let mut build_id: Option<String> = None;

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            // Check DWARF debug sections
            if DWARF_SECTIONS.contains(&name) {
                dwarf_sections.push(name.to_string());
            }
            // Check symbol table (unstripped binary indicator)
            if name == ".symtab" {
                has_symtab = true;
            }
            if name == ".strtab" {
                has_strtab = true;
            }
            // Check build ID
            if name == ".note.gnu.build-id" {
                build_id = Some("present".to_string());
            }
        }
    }

    dwarf_sections.sort();

    ElfDebugInfo {
        dwarf_sections,
        has_symtab,
        has_strtab,
        build_id,
    }
}

/// Check for RPATH and RUNPATH in dynamic section
fn check_rpath_runpath(elf: &Elf) -> (Option<String>, Option<String>) {
    let mut rpath = None;
    let mut runpath = None;

    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == DT_RPATH
                && let Some(val) = elf.dynstrtab.get_at(dyn_entry.d_val as usize)
            {
                rpath = Some(val.to_string());
            } else if dyn_entry.d_tag == DT_RUNPATH
                && let Some(val) = elf.dynstrtab.get_at(dyn_entry.d_val as usize)
            {
                runpath = Some(val.to_string());
            }
        }
    }

    (rpath, runpath)
}

/// Run all security checks on an ELF binary
pub fn check_elf(elf: &Elf) -> ElfCheckResult {
    let relro = check_relro(elf);
    let stack_canary = check_stack_canary(elf);
    let nx = check_nx(elf);
    let pie = check_pie(elf);
    let (fortify_source, fortified_functions) = check_fortify(elf);
    let (rpath, runpath) = check_rpath_runpath(elf);
    let debug_info = check_debug_info(elf);

    ElfCheckResult {
        relro,
        stack_canary,
        nx,
        pie,
        fortify_source,
        fortified_functions,
        rpath,
        runpath,
        debug_info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::Object;

    /// Helper: parse an ELF from raw bytes and run check_elf
    fn parse_and_check(bytes: &[u8]) -> Option<ElfCheckResult> {
        match Object::parse(bytes) {
            Ok(Object::Elf(elf)) => Some(check_elf(&elf)),
            _ => None,
        }
    }

    /// Build a minimal 64-bit ELF binary (ET_EXEC, no special hardening)
    fn minimal_elf_exec() -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // ELF magic
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        // EI_CLASS = ELFCLASS64
        buf[4] = 2;
        // EI_DATA = ELFDATA2LSB
        buf[5] = 1;
        // EI_VERSION
        buf[6] = 1;
        // EI_OSABI = ELFOSABI_NONE
        buf[7] = 0;
        // e_type = ET_EXEC (2)
        buf[16] = 2;
        buf[17] = 0;
        // e_machine = EM_X86_64 (0x3E)
        buf[18] = 0x3E;
        buf[19] = 0;
        // e_version = 1
        buf[20] = 1;
        // e_ehsize = 64
        buf[52] = 64;
        buf[53] = 0;
        // e_phentsize = 56
        buf[54] = 56;
        buf[55] = 0;
        // e_phnum = 0 (no program headers)
        buf[56] = 0;
        // e_shentsize = 64
        buf[58] = 64;
        buf[59] = 0;
        buf
    }

    /// Build a minimal 64-bit PIE ELF (ET_DYN)
    fn minimal_elf_dyn() -> Vec<u8> {
        let mut buf = minimal_elf_exec();
        // e_type = ET_DYN (3)
        buf[16] = 3;
        buf[17] = 0;
        buf
    }

    // ---- RelroStatus display ----

    #[test]
    fn relro_status_display() {
        assert_eq!(RelroStatus::Full.to_string(), "Full");
        assert_eq!(RelroStatus::Partial.to_string(), "Partial");
        assert_eq!(RelroStatus::None.to_string(), "None");
    }

    // ---- PIE check ----

    #[test]
    fn pie_detected_for_et_dyn() {
        let bytes = minimal_elf_dyn();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(result.pie, "ET_DYN should be detected as PIE");
    }

    #[test]
    fn pie_not_detected_for_et_exec() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(!result.pie, "ET_EXEC should not be detected as PIE");
    }

    // ---- NX check ----

    #[test]
    fn nx_false_when_no_gnu_stack() {
        // Minimal ELF with no program headers -> no GNU_STACK -> NX = false
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(
            !result.nx,
            "No GNU_STACK segment means NX is not explicitly set"
        );
    }

    // ---- RELRO check ----

    #[test]
    fn relro_none_when_no_program_headers() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert_eq!(result.relro, RelroStatus::None);
    }

    // ---- Stack canary check ----

    #[test]
    fn no_stack_canary_in_minimal_elf() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(!result.stack_canary, "Minimal ELF has no __stack_chk_fail");
    }

    // ---- Fortify check ----

    #[test]
    fn no_fortify_in_minimal_elf() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(!result.fortify_source);
        assert!(result.fortified_functions.is_empty());
    }

    // ---- RPATH/RUNPATH ----

    #[test]
    fn no_rpath_runpath_in_minimal_elf() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(result.rpath.is_none());
        assert!(result.runpath.is_none());
    }

    // ---- Debug info check ----

    #[test]
    fn no_debug_info_in_minimal_elf() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(result.debug_info.dwarf_sections.is_empty());
        assert!(!result.debug_info.has_symtab);
        assert!(!result.debug_info.has_strtab);
        assert!(result.debug_info.build_id.is_none());
        assert!(!result.debug_info.has_debug_info());
    }

    #[test]
    fn elf_debug_info_has_debug_info_with_dwarf() {
        let info = ElfDebugInfo {
            dwarf_sections: vec![".debug_info".to_string()],
            has_symtab: false,
            has_strtab: false,
            build_id: None,
        };
        assert!(info.has_debug_info());
    }

    #[test]
    fn elf_debug_info_has_debug_info_with_symtab() {
        let info = ElfDebugInfo {
            dwarf_sections: vec![],
            has_symtab: true,
            has_strtab: false,
            build_id: None,
        };
        assert!(info.has_debug_info());
    }

    #[test]
    fn elf_debug_info_no_debug_info_clean() {
        let info = ElfDebugInfo {
            dwarf_sections: vec![],
            has_symtab: false,
            has_strtab: false,
            build_id: Some("present".to_string()),
        };
        // build_id alone does not count as debug info
        assert!(!info.has_debug_info());
    }

    /// Helper to create a no-debug ElfDebugInfo for test fixtures
    fn no_debug_info() -> ElfDebugInfo {
        ElfDebugInfo {
            dwarf_sections: vec![],
            has_symtab: false,
            has_strtab: false,
            build_id: None,
        }
    }

    // ---- has_failures ----

    #[test]
    fn has_failures_all_good() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: true,
            fortified_functions: vec!["__printf_chk".to_string()],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn has_failures_relro_none() {
        let result = ElfCheckResult {
            relro: RelroStatus::None,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: true,
            fortified_functions: vec![],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_partial_relro_not_failure() {
        // Partial RELRO is not counted as a failure
        let result = ElfCheckResult {
            relro: RelroStatus::Partial,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn has_failures_no_stack_canary() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: false,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_nx() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: false,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_pie() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: false,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: None,
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_with_rpath() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: Some("/usr/lib".to_string()),
            runpath: None,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_with_runpath() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            rpath: None,
            runpath: Some("/opt/lib".to_string()),
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    // ---- Test with real system binary (integration-style, only on Linux) ----

    #[test]
    #[cfg(target_os = "linux")]
    fn check_system_binary_ls() {
        let bytes = std::fs::read("/bin/ls");
        if let Ok(bytes) = bytes
            && let Ok(Object::Elf(elf)) = Object::parse(&bytes)
        {
            let result = check_elf(&elf);
            // /bin/ls on modern Linux should have most hardening enabled
            // We just verify it doesn't panic and returns sensible values
            assert!(
                result.relro == RelroStatus::Full
                    || result.relro == RelroStatus::Partial
                    || result.relro == RelroStatus::None
            );
            // NX should be enabled on any modern distro
            assert!(result.nx, "/bin/ls should have NX enabled");
        }
    }
}
