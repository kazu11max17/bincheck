use goblin::elf::Elf;
use goblin::elf::dynamic::{DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_NEEDED, DT_RPATH, DT_RUNPATH};
use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP};
use serde::Serialize;

// ELF e_machine constants (not publicly exported by goblin)
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Linkage classification (F4 / BHC013).
///
/// Distinguishes a fully static `-static` build (`ET_EXEC`, no `PT_INTERP`) from
/// a `-static-pie` build (`ET_DYN` with no `PT_INTERP` and no `DT_NEEDED`).
/// Dynamic PIE and dynamic non-PIE both map to `Dynamic`; `pie` is reported
/// independently in `ElfCheckResult::pie`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Linkage {
    Dynamic,
    Static,
    StaticPie,
}

impl std::fmt::Display for Linkage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Linkage::Dynamic => write!(f, "dynamic"),
            Linkage::Static => write!(f, "static"),
            Linkage::StaticPie => write!(f, "static-pie"),
        }
    }
}

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
    /// Estimated FORTIFY_SOURCE level (1 or 2), or None if unknown/not fortified.
    /// Level 2 is inferred when format-string checking functions (e.g. __fprintf_chk,
    /// __snprintf_chk) are present. Level 1 is inferred for other __*_chk functions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fortify_level: Option<u8>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    /// F4 / BHC013: distinguish static, static-pie and dynamic linkage.
    /// `Option<_>` so older JSON consumers that did not expect this field stay unaffected
    /// (`skip_serializing_if`). `None` means we could not determine linkage robustly
    /// (e.g. malformed ELF with `ET_DYN` but no `PT_DYNAMIC`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage: Option<Linkage>,
    /// True when `DT_FLAGS_1 & DF_1_PIE` is observed. Treated as a confirming signal
    /// for `Linkage::StaticPie` / dynamic PIE; absence does not invalidate the heuristic.
    pub df_1_pie: bool,
    pub debug_info: ElfDebugInfo,
}

impl ElfCheckResult {
    /// Returns true if any security check is in a failing state
    pub fn has_failures(&self) -> bool {
        self.relro == RelroStatus::None
            || !self.stack_canary
            || !self.nx
            || !self.pie
            || self.rpath_is_failure()
            || self.runpath_is_failure()
    }

    /// Returns true if RPATH is set and is NOT a $ORIGIN-relative path (which is acceptable).
    pub fn rpath_is_failure(&self) -> bool {
        match self.rpath.as_deref() {
            None => false,
            Some(p) => !is_origin_relative(p),
        }
    }

    /// Returns true if RUNPATH is set and is NOT a $ORIGIN-relative path (which is acceptable).
    pub fn runpath_is_failure(&self) -> bool {
        match self.runpath.as_deref() {
            None => false,
            Some(p) => !is_origin_relative(p),
        }
    }
}

/// Returns true if the given rpath/runpath value is `$ORIGIN` or starts with `$ORIGIN/`.
/// Such relative paths are acceptable because they do not introduce absolute attacker-controlled
/// search paths.
fn is_origin_relative(path: &str) -> bool {
    path == "$ORIGIN" || path.starts_with("$ORIGIN/")
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

/// Check NX (No-Execute stack): PT_GNU_STACK without PF_X.
///
/// When PT_GNU_STACK is present, its PF_X flag directly indicates whether the stack is
/// executable. When it is absent the answer is architecture-dependent:
/// - x86_64 (EM_X86_64) and AArch64 (EM_AARCH64): the CPU enforces NX/XN in hardware and
///   modern Linux kernels default to non-executable stacks, so absence of PT_GNU_STACK means NX
///   is still active.
/// - x86 (EM_386): NX depends on PAE/CPU feature; without an explicit PT_GNU_STACK we cannot be
///   certain, so we fall back to the conservative `false`.
/// - Other architectures: conservative `false`.
fn check_nx(elf: &Elf) -> bool {
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            // NX is enabled if the stack segment does NOT have execute permission
            return (ph.p_flags & PF_X) == 0;
        }
    }
    // No PT_GNU_STACK segment – use architecture to determine default.
    matches!(elf.header.e_machine, EM_X86_64 | EM_AARCH64)
}

/// Check if binary is Position Independent Executable
fn check_pie(elf: &Elf) -> bool {
    // ET_DYN (3) = shared object / PIE
    // ET_EXEC (2) = fixed address executable
    elf.header.e_type == ET_DYN
}

/// F4 (BHC013): classify linkage as `dynamic` / `static` / `static-pie`.
///
/// Returns `(linkage, df_1_pie)`.
///
/// Heuristic (multi-condition AND for `static-pie` to avoid misclassifying a plain `.so`):
/// - `Dynamic`: `PT_INTERP` is present, OR `ET_EXEC` with `DT_NEEDED` entries.
/// - `Static`: `ET_EXEC` and no `PT_INTERP` and no `DT_NEEDED`.
/// - `StaticPie`: `ET_DYN` and no `PT_INTERP` and no `DT_NEEDED` and
///   `e_entry != 0` and `PT_DYNAMIC` is present.
/// - `None` (unknown): `ET_DYN` without `PT_INTERP` but `PT_DYNAMIC` missing
///   (likely a malformed binary or a shared library; bincheck does not classify libraries here).
///
/// `DF_1_PIE` (`DT_FLAGS_1`) is observed independently and surfaced as a
/// confirming signal for the `static-pie` and dynamic PIE cases. Its absence does
/// not flip the classification because not every linker emits it.
fn check_linkage(elf: &Elf) -> (Option<Linkage>, bool) {
    let has_interp = elf.program_headers.iter().any(|ph| ph.p_type == PT_INTERP);
    let has_dynamic_seg = elf.program_headers.iter().any(|ph| ph.p_type == PT_DYNAMIC);
    let has_needed = elf
        .dynamic
        .as_ref()
        .map(|d| d.dyns.iter().any(|x| x.d_tag == DT_NEEDED))
        .unwrap_or(false);
    let df_1_pie = elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .any(|x| x.d_tag == goblin::elf::dynamic::DT_FLAGS_1 && (x.d_val & DF_1_PIE) != 0)
        })
        .unwrap_or(false);
    let e_entry = elf.header.e_entry;
    let e_type = elf.header.e_type;

    let linkage = match e_type {
        ET_DYN if has_interp => Some(Linkage::Dynamic),
        ET_DYN if !has_needed && e_entry != 0 && has_dynamic_seg => Some(Linkage::StaticPie),
        ET_DYN => None, // ET_DYN with PT_DYNAMIC missing or DT_NEEDED present without PT_INTERP: unclassifiable
        ET_EXEC if has_interp => Some(Linkage::Dynamic),
        ET_EXEC if has_needed => Some(Linkage::Dynamic),
        ET_EXEC => Some(Linkage::Static),
        _ => None,
    };

    (linkage, df_1_pie)
}

/// Format-string checking functions that are only introduced by `-D_FORTIFY_SOURCE=2`.
/// Their presence suggests level 2 (though it is not guaranteed by the ABI).
const FORTIFY_LEVEL2_SYMS: &[&str] = &[
    "__fprintf_chk",
    "__printf_chk",
    "__sprintf_chk",
    "__snprintf_chk",
    "__vfprintf_chk",
    "__vprintf_chk",
    "__vsprintf_chk",
    "__vsnprintf_chk",
    "__dprintf_chk",
    "__vdprintf_chk",
    "__obstack_printf_chk",
    "__obstack_vprintf_chk",
    "__wprintf_chk",
    "__fwprintf_chk",
    "__swprintf_chk",
    "__vwprintf_chk",
    "__vfwprintf_chk",
    "__vswprintf_chk",
];

/// Check for fortified functions (__*_chk pattern in dynamic and static symbols).
///
/// Returns `(has_fortify, fortified_function_names, fortify_level)`.
/// `fortify_level` is `Some(2)` when level-2-specific symbols are found, `Some(1)` when only
/// level-1 symbols are found, or `None` when no fortified functions are detected.
fn check_fortify(elf: &Elf) -> (bool, Vec<String>, Option<u8>) {
    let mut fortified = Vec::new();

    // Search dynsyms (dynamically linked binaries)
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            && name.ends_with("_chk")
            && name.starts_with("__")
        {
            let s = name.to_string();
            if !fortified.contains(&s) {
                fortified.push(s);
            }
        }
    }

    // Search symtab (statically linked / unstripped binaries – P1-1 coverage)
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && name.ends_with("_chk")
            && name.starts_with("__")
        {
            let s = name.to_string();
            if !fortified.contains(&s) {
                fortified.push(s);
            }
        }
    }

    if fortified.is_empty() {
        return (false, fortified, None);
    }

    // Infer level: presence of any level-2-specific symbol suggests level 2.
    let level = if fortified
        .iter()
        .any(|f| FORTIFY_LEVEL2_SYMS.contains(&f.as_str()))
    {
        Some(2u8)
    } else {
        Some(1u8)
    };

    (true, fortified, level)
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
    let (fortify_source, fortified_functions, fortify_level) = check_fortify(elf);
    let (rpath, runpath) = check_rpath_runpath(elf);
    let (linkage, df_1_pie) = check_linkage(elf);
    let debug_info = check_debug_info(elf);

    ElfCheckResult {
        relro,
        stack_canary,
        nx,
        pie,
        fortify_source,
        fortified_functions,
        fortify_level,
        rpath,
        runpath,
        linkage,
        df_1_pie,
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
    fn nx_true_when_no_gnu_stack_x86_64() {
        // Minimal x86_64 ELF with no program headers -> no GNU_STACK.
        // x86_64 defaults to NX enabled, so result should be true.
        let bytes = minimal_elf_exec(); // e_machine = EM_X86_64 (0x3E)
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(
            result.nx,
            "x86_64 without GNU_STACK should still report NX enabled"
        );
    }

    #[test]
    fn nx_false_when_no_gnu_stack_unknown_arch() {
        // Minimal ELF with EM_NONE (unknown arch) -> no GNU_STACK -> NX = false
        let mut bytes = minimal_elf_exec();
        // e_machine = EM_NONE (0x00)
        bytes[18] = 0x00;
        bytes[19] = 0x00;
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(
            !result.nx,
            "Unknown arch without GNU_STACK should report NX disabled (conservative)"
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
            fortify_level: Some(2),
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: Some("/usr/lib".to_string()),
            runpath: None,
            linkage: None,
            df_1_pie: false,
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
            fortify_level: None,
            rpath: None,
            runpath: Some("/opt/lib".to_string()),
            linkage: None,
            df_1_pie: false,
            debug_info: no_debug_info(),
        };
        assert!(result.has_failures());
    }

    // ---- P2-4: $ORIGIN rpath/runpath is not a failure ----

    #[test]
    fn has_failures_rpath_origin_only_not_failure() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: Some("$ORIGIN".to_string()),
            runpath: None,
            linkage: None,
            df_1_pie: false,
            debug_info: no_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "$ORIGIN rpath should not be a failure"
        );
    }

    #[test]
    fn has_failures_rpath_origin_subdir_not_failure() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: Some("$ORIGIN/lib".to_string()),
            runpath: None,
            linkage: None,
            df_1_pie: false,
            debug_info: no_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "$ORIGIN/lib rpath should not be a failure"
        );
    }

    #[test]
    fn has_failures_runpath_origin_not_failure() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: None,
            runpath: Some("$ORIGIN".to_string()),
            linkage: None,
            df_1_pie: false,
            debug_info: no_debug_info(),
        };
        assert!(
            !result.has_failures(),
            "$ORIGIN runpath should not be a failure"
        );
    }

    #[test]
    fn has_failures_rpath_non_origin_absolute_is_failure() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: Some("/usr/local/lib".to_string()),
            runpath: None,
            linkage: None,
            df_1_pie: false,
            debug_info: no_debug_info(),
        };
        assert!(
            result.has_failures(),
            "Absolute rpath should still be a failure"
        );
    }

    // ---- P2-1: fortify_level inference ----

    #[test]
    fn fortify_level_none_when_no_fortify() {
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert!(result.fortify_level.is_none());
    }

    /// Build a synthetic 64-bit ELF that satisfies the `static-pie` heuristic:
    /// `ET_DYN` + `PT_DYNAMIC` present + `e_entry != 0` + no `PT_INTERP` +
    /// no `DT_NEEDED`. Used by `linkage_static_pie_synthetic_elf` (Ren P0-2).
    ///
    /// Layout:
    /// - [0..64)   ELF64 header
    /// - [64..120) one program header (PT_DYNAMIC)
    /// - [120..136) dynamic table: a single `DT_NULL` (16 zero bytes)
    fn minimal_elf_static_pie() -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // ELF magic + ident
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EI_VERSION
        buf[7] = 0; // ELFOSABI_NONE
        // e_type = ET_DYN
        buf[16] = 3;
        // e_machine = EM_X86_64
        buf[18] = 0x3E;
        // e_version
        buf[20] = 1;
        // e_entry = 0x1000 (must be != 0 for the heuristic to fire)
        buf[24] = 0x00;
        buf[25] = 0x10;
        // e_phoff = 64
        buf[32] = 64;
        // e_ehsize = 64
        buf[52] = 64;
        // e_phentsize = 56, e_phnum = 1
        buf[54] = 56;
        buf[56] = 1;
        // e_shentsize = 64
        buf[58] = 64;

        // --- Program header at offset 64: PT_DYNAMIC ---
        // p_type = PT_DYNAMIC (2)
        buf[64] = 2;
        // p_flags = PF_R | PF_W = 6
        buf[68] = 6;
        // p_offset = 120 (start of dynamic table inside the file)
        buf[72] = 120;
        // p_vaddr = 0x2000
        buf[81] = 0x20;
        // p_paddr = 0x2000
        buf[89] = 0x20;
        // p_filesz = 16 (one DT_NULL entry: 8 bytes d_tag + 8 bytes d_val, all zero)
        buf[96] = 16;
        // p_memsz = 16
        buf[104] = 16;
        // p_align = 8
        buf[112] = 8;

        // [120..136) is already zero-initialized → DT_NULL terminator.
        buf
    }

    // ---- F4 (BHC013): Linkage classification ----

    #[test]
    fn linkage_static_pie_synthetic_elf() {
        let bytes = minimal_elf_static_pie();
        let result = parse_and_check(&bytes).expect("synthetic static-pie ELF should parse");
        assert_eq!(
            result.linkage,
            Some(Linkage::StaticPie),
            "ET_DYN + PT_DYNAMIC + e_entry!=0 + no PT_INTERP + no DT_NEEDED → StaticPie"
        );
        // pie is also true (ET_DYN), and df_1_pie is false because we did not emit
        // a DT_FLAGS_1 entry — this is by design: static-pie is asserted by the
        // multi-condition AND, DF_1_PIE is only a confirming signal.
        assert!(result.pie);
        assert!(!result.df_1_pie);
    }

    #[test]
    fn linkage_static_for_et_exec_no_interp() {
        // minimal_elf_exec has ET_EXEC, no PT_INTERP, no DT_NEEDED → static
        let bytes = minimal_elf_exec();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert_eq!(result.linkage, Some(Linkage::Static));
        assert!(!result.df_1_pie);
    }

    #[test]
    fn linkage_unknown_for_minimal_et_dyn_without_dynamic_segment() {
        // minimal_elf_dyn has ET_DYN but no PT_DYNAMIC and e_entry == 0
        // → cannot classify as static-pie (heuristic requires PT_DYNAMIC + e_entry != 0)
        let bytes = minimal_elf_dyn();
        let result = parse_and_check(&bytes).expect("should parse as ELF");
        assert_eq!(result.linkage, None);
    }

    #[test]
    fn linkage_display_kebab_case() {
        assert_eq!(Linkage::Dynamic.to_string(), "dynamic");
        assert_eq!(Linkage::Static.to_string(), "static");
        assert_eq!(Linkage::StaticPie.to_string(), "static-pie");
    }

    #[test]
    fn linkage_serializes_kebab_case() {
        let json = serde_json::to_string(&Linkage::StaticPie).unwrap();
        assert_eq!(json, "\"static-pie\"");
    }

    #[test]
    fn linkage_field_omitted_when_none() {
        // Build a result with linkage=None and verify the JSON omits the field
        let result = ElfCheckResult {
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
            debug_info: no_debug_info(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("\"linkage\""),
            "linkage field should be omitted when None: {}",
            json
        );
    }

    #[test]
    fn linkage_field_serialized_when_some() {
        let result = ElfCheckResult {
            relro: RelroStatus::Full,
            stack_canary: true,
            nx: true,
            pie: true,
            fortify_source: false,
            fortified_functions: vec![],
            fortify_level: None,
            rpath: None,
            runpath: None,
            linkage: Some(Linkage::StaticPie),
            df_1_pie: true,
            debug_info: no_debug_info(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"linkage\":\"static-pie\""));
        assert!(json.contains("\"df_1_pie\":true"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linkage_dynamic_for_system_ls() {
        // /bin/ls on Linux is always dynamically linked → expect Some(Dynamic)
        if let Ok(bytes) = std::fs::read("/bin/ls")
            && let Ok(Object::Elf(elf)) = Object::parse(&bytes)
        {
            let result = check_elf(&elf);
            assert_eq!(result.linkage, Some(Linkage::Dynamic));
        }
    }

    #[test]
    fn is_origin_relative_variants() {
        assert!(super::is_origin_relative("$ORIGIN"));
        assert!(super::is_origin_relative("$ORIGIN/lib"));
        assert!(super::is_origin_relative("$ORIGIN/../lib"));
        assert!(!super::is_origin_relative("/usr/lib"));
        assert!(!super::is_origin_relative("$ORIGIN_EXTRA"));
        assert!(!super::is_origin_relative(""));
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
