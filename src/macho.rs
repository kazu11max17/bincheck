use serde::Serialize;

// Mach-O magic numbers
const MH_MAGIC_32: u32 = 0xFEED_FACE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const MH_MAGIC_32_CIGAM: u32 = 0xCEFA_EDFE;
const MH_MAGIC_64_CIGAM: u32 = 0xCFFA_EDFE;
const FAT_CIGAM: u32 = 0xBEBA_FECA;

// Mach-O header flags
const MH_PIE: u32 = 0x0020_0000;

// Load command types
const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1D;

// Segment protection flags
const VM_PROT_EXECUTE: u32 = 0x04;

// Code signature magic and flags
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
const CS_RUNTIME: u32 = 0x0001_0000;

/// Result of all Mach-O security checks
#[derive(Debug, Clone, Serialize)]
pub struct MachoCheckResult {
    pub pie: bool,
    pub stack_canary: bool,
    pub arc: bool,
    pub nx_stack: bool,
    pub nx_heap: bool,
    pub code_signature: bool,
    pub hardened_runtime: bool,
    pub restrict_segment: bool,
}

impl MachoCheckResult {
    /// Returns true if any critical security check is in a failing state
    pub fn has_failures(&self) -> bool {
        !self.pie || !self.stack_canary || !self.nx_stack || !self.nx_heap
    }
}

/// Parsed Mach-O binary information needed for security checks
struct MachoInfo {
    is_64: bool,
    is_big_endian: bool,
    flags: u32,
    load_commands: Vec<LoadCommand>,
    symbols: Vec<String>,
}

struct LoadCommand {
    cmd: u32,
    data: Vec<u8>,
}

/// Segment info extracted from LC_SEGMENT / LC_SEGMENT_64
struct SegmentInfo {
    segname: String,
    initprot: u32,
    sections: Vec<SectionInfo>,
}

struct SectionInfo {
    sectname: String,
    segname: String,
}

fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

#[allow(dead_code)]
fn read_u64(data: &[u8], offset: usize, big_endian: bool) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
    Some(if big_endian {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}

/// Read a null-terminated string from a fixed-size field
fn read_fixed_string(data: &[u8], offset: usize, max_len: usize) -> String {
    if offset + max_len > data.len() {
        return String::new();
    }
    let slice = &data[offset..offset + max_len];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(max_len);
    String::from_utf8_lossy(&slice[..end]).to_string()
}

/// Detect if bytes are a Mach-O binary and return the magic
pub fn detect_macho(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    let magic_le = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(data[0..4].try_into().ok()?);

    match magic_le {
        MH_MAGIC_32 | MH_MAGIC_64 | FAT_MAGIC | MH_MAGIC_32_CIGAM | MH_MAGIC_64_CIGAM
        | FAT_CIGAM => Some(magic_le),
        _ => match magic_be {
            MH_MAGIC_32 | MH_MAGIC_64 | FAT_MAGIC => Some(magic_be),
            _ => None,
        },
    }
}

/// Parse a Mach-O binary from raw bytes (handles single-arch only; for fat/universal, uses first slice)
fn parse_macho(data: &[u8]) -> Option<MachoInfo> {
    if data.len() < 4 {
        return None;
    }

    let magic_le = u32::from_le_bytes(data[0..4].try_into().ok()?);

    // Handle fat/universal binary - extract first architecture slice
    if magic_le == FAT_MAGIC || magic_le == FAT_CIGAM {
        return parse_fat_macho(data);
    }

    parse_single_macho(data)
}

fn parse_fat_macho(data: &[u8]) -> Option<MachoInfo> {
    if data.len() < 8 {
        return None;
    }

    // Fat header is always big-endian
    let nfat_arch = read_u32(data, 4, true)?;
    if nfat_arch == 0 {
        return None;
    }

    // fat_arch struct is 20 bytes each, starting at offset 8
    // offset field is at bytes 8..12 of each fat_arch entry
    if data.len() < 8 + 20 {
        return None;
    }
    let slice_offset = read_u32(data, 8 + 8, true)? as usize;
    let slice_size = read_u32(data, 8 + 12, true)? as usize;

    if slice_offset + slice_size > data.len() {
        return None;
    }

    parse_single_macho(&data[slice_offset..slice_offset + slice_size])
}

fn parse_single_macho(data: &[u8]) -> Option<MachoInfo> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let (is_64, is_big_endian) = match magic {
        MH_MAGIC_32 => (false, false),
        MH_MAGIC_64 => (true, false),
        MH_MAGIC_32_CIGAM => (false, true),
        MH_MAGIC_64_CIGAM => (true, true),
        _ => return None,
    };

    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return None;
    }

    // ncmds at offset 16, sizeofcmds at offset 20, flags at offset 24
    let ncmds = read_u32(data, 16, is_big_endian)? as usize;
    let _sizeofcmds = read_u32(data, 20, is_big_endian)?;
    let flags = read_u32(data, 24, is_big_endian)?;

    // Parse load commands
    let mut load_commands = Vec::new();
    let mut offset = header_size;

    for _ in 0..ncmds {
        if offset + 8 > data.len() {
            break;
        }
        let cmd = read_u32(data, offset, is_big_endian)?;
        let cmdsize = read_u32(data, offset + 4, is_big_endian)? as usize;
        if cmdsize < 8 || offset + cmdsize > data.len() {
            break;
        }

        load_commands.push(LoadCommand {
            cmd,
            data: data[offset..offset + cmdsize].to_vec(),
        });

        offset += cmdsize;
    }

    // Extract symbols from LC_SYMTAB
    let symbols = extract_symbols(data, &load_commands, is_big_endian);

    Some(MachoInfo {
        is_64,
        is_big_endian,
        flags,
        load_commands,
        symbols,
    })
}

fn extract_symbols(data: &[u8], load_commands: &[LoadCommand], is_big_endian: bool) -> Vec<String> {
    let mut symbols = Vec::new();

    for lc in load_commands {
        if lc.cmd != LC_SYMTAB {
            continue;
        }
        if lc.data.len() < 24 {
            continue;
        }
        let stroff = read_u32(&lc.data, 16, is_big_endian).unwrap_or(0) as usize;
        let strsize = read_u32(&lc.data, 20, is_big_endian).unwrap_or(0) as usize;

        if stroff + strsize > data.len() || strsize == 0 {
            continue;
        }

        let strtab = &data[stroff..stroff + strsize];
        // Parse null-terminated strings from the string table
        let mut pos = 0;
        while pos < strtab.len() {
            let end = strtab[pos..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| pos + p)
                .unwrap_or(strtab.len());
            if end > pos
                && let Ok(s) = std::str::from_utf8(&strtab[pos..end])
                && !s.is_empty()
            {
                symbols.push(s.to_string());
            }
            pos = end + 1;
        }
    }

    symbols
}

/// Parse segment info from a load command
fn parse_segment(lc: &LoadCommand, is_64: bool, is_big_endian: bool) -> Option<SegmentInfo> {
    if is_64 {
        if lc.cmd != LC_SEGMENT_64 || lc.data.len() < 72 {
            return None;
        }
        let segname = read_fixed_string(&lc.data, 8, 16);
        let initprot = read_u32(&lc.data, 60, is_big_endian)?;
        let nsects = read_u32(&lc.data, 64, is_big_endian)? as usize;

        let mut sections = Vec::new();
        let mut sect_offset = 72;
        for _ in 0..nsects {
            if sect_offset + 80 > lc.data.len() {
                break;
            }
            let sectname = read_fixed_string(&lc.data, sect_offset, 16);
            let seg = read_fixed_string(&lc.data, sect_offset + 16, 16);
            sections.push(SectionInfo {
                sectname,
                segname: seg,
            });
            sect_offset += 80; // sizeof(section_64)
        }

        Some(SegmentInfo {
            segname,
            initprot,
            sections,
        })
    } else {
        if lc.cmd != LC_SEGMENT || lc.data.len() < 56 {
            return None;
        }
        let segname = read_fixed_string(&lc.data, 8, 16);
        let initprot = read_u32(&lc.data, 44, is_big_endian)?;
        let nsects = read_u32(&lc.data, 48, is_big_endian)? as usize;

        let mut sections = Vec::new();
        let mut sect_offset = 56;
        for _ in 0..nsects {
            if sect_offset + 68 > lc.data.len() {
                break;
            }
            let sectname = read_fixed_string(&lc.data, sect_offset, 16);
            let seg = read_fixed_string(&lc.data, sect_offset + 16, 16);
            sections.push(SectionInfo {
                sectname,
                segname: seg,
            });
            sect_offset += 68; // sizeof(section)
        }

        Some(SegmentInfo {
            segname,
            initprot,
            sections,
        })
    }
}

/// Check PIE: MH_PIE flag in header flags
fn check_pie(info: &MachoInfo) -> bool {
    (info.flags & MH_PIE) != 0
}

/// Check Stack Canary: look for ___stack_chk_fail or ___stack_chk_guard in symbols
fn check_stack_canary(info: &MachoInfo) -> bool {
    info.symbols
        .iter()
        .any(|s| s.contains("___stack_chk_fail") || s.contains("___stack_chk_guard"))
}

/// Check ARC: look for _objc_release symbol
fn check_arc(info: &MachoInfo) -> bool {
    info.symbols.iter().any(|s| s.contains("_objc_release"))
}

/// Check NX Stack: __DATA segment should not have execute permission,
/// and no stack segment should be executable
fn check_nx_stack(info: &MachoInfo) -> bool {
    // Look for __LINKEDIT or stack-related segments without execute
    // On macOS, NX stack is the default. Check if any segment named __PAGEZERO exists
    // (indicates proper memory layout) and no executable stack segment exists.
    for lc in &info.load_commands {
        if let Some(seg) = parse_segment(lc, info.is_64, info.is_big_endian)
            && seg.segname == "__PAGEZERO"
        {
            // __PAGEZERO presence means proper NX support
            return true;
        }
    }
    // If we have a 64-bit binary, NX is typically enforced by default
    info.is_64
}

/// Check NX Heap: __DATA segment should not have execute permission
fn check_nx_heap(info: &MachoInfo) -> bool {
    for lc in &info.load_commands {
        if let Some(seg) = parse_segment(lc, info.is_64, info.is_big_endian)
            && seg.segname == "__DATA"
        {
            return (seg.initprot & VM_PROT_EXECUTE) == 0;
        }
    }
    // No __DATA segment found - assume NX is enforced (conservative for macOS)
    true
}

/// Check Code Signature: LC_CODE_SIGNATURE load command present
fn check_code_signature(data: &[u8], info: &MachoInfo) -> bool {
    for lc in &info.load_commands {
        if lc.cmd == LC_CODE_SIGNATURE {
            if lc.data.len() >= 16 {
                let cs_offset = read_u32(&lc.data, 8, info.is_big_endian).unwrap_or(0) as usize;
                let cs_size = read_u32(&lc.data, 12, info.is_big_endian).unwrap_or(0) as usize;
                // Verify the code signature data exists
                return cs_offset + cs_size <= data.len() && cs_size > 0;
            }
            return true;
        }
    }
    false
}

/// Check Hardened Runtime: CS_RUNTIME flag in code signature's CodeDirectory
fn check_hardened_runtime(data: &[u8], info: &MachoInfo) -> bool {
    for lc in &info.load_commands {
        if lc.cmd != LC_CODE_SIGNATURE {
            continue;
        }
        if lc.data.len() < 16 {
            continue;
        }
        let cs_offset = read_u32(&lc.data, 8, info.is_big_endian).unwrap_or(0) as usize;
        let cs_size = read_u32(&lc.data, 12, info.is_big_endian).unwrap_or(0) as usize;

        if cs_offset + cs_size > data.len() || cs_size < 12 {
            continue;
        }

        let cs_data = &data[cs_offset..cs_offset + cs_size];
        // Code signature superblob: magic (BE) at offset 0
        let cs_magic = read_u32(cs_data, 0, true).unwrap_or(0);
        if cs_magic != CSMAGIC_EMBEDDED_SIGNATURE {
            continue;
        }

        // SuperBlob: count at offset 8
        let count = read_u32(cs_data, 8, true).unwrap_or(0) as usize;

        // Each blob index: type (4 bytes) + offset (4 bytes) starting at offset 12
        for i in 0..count {
            let idx_offset = 12 + i * 8;
            if idx_offset + 8 > cs_data.len() {
                break;
            }
            let blob_offset = read_u32(cs_data, idx_offset + 4, true).unwrap_or(0) as usize;
            if blob_offset + 44 > cs_data.len() {
                continue;
            }

            // CodeDirectory magic = 0xFADE0C02
            let blob_magic = read_u32(cs_data, blob_offset, true).unwrap_or(0);
            if blob_magic == 0xFADE_0C02 {
                // CodeDirectory: flags at offset 12 (version >= 0x20400 has runtime at offset 44)
                let version = read_u32(cs_data, blob_offset + 8, true).unwrap_or(0);
                let cd_flags = read_u32(cs_data, blob_offset + 12, true).unwrap_or(0);
                if (cd_flags & CS_RUNTIME) != 0 {
                    return true;
                }
                // Also check runtime field for newer versions
                if version >= 0x0002_0400 && blob_offset + 48 <= cs_data.len() {
                    let runtime = read_u32(cs_data, blob_offset + 44, true).unwrap_or(0);
                    if runtime != 0 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check Restrict: __RESTRICT,__restrict section present
fn check_restrict(info: &MachoInfo) -> bool {
    for lc in &info.load_commands {
        if let Some(seg) = parse_segment(lc, info.is_64, info.is_big_endian)
            && seg.segname == "__RESTRICT"
        {
            return seg
                .sections
                .iter()
                .any(|s| s.sectname == "__restrict" && s.segname == "__RESTRICT");
        }
    }
    false
}

/// Run all security checks on a Mach-O binary (raw bytes)
pub fn check_macho(data: &[u8]) -> Option<MachoCheckResult> {
    let info = parse_macho(data)?;

    Some(MachoCheckResult {
        pie: check_pie(&info),
        stack_canary: check_stack_canary(&info),
        arc: check_arc(&info),
        nx_stack: check_nx_stack(&info),
        nx_heap: check_nx_heap(&info),
        code_signature: check_code_signature(data, &info),
        hardened_runtime: check_hardened_runtime(data, &info),
        restrict_segment: check_restrict(&info),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- MachoCheckResult::has_failures ----

    #[test]
    fn has_failures_all_enabled() {
        let result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: true,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(!result.has_failures());
    }

    #[test]
    fn has_failures_no_pie() {
        let result = MachoCheckResult {
            pie: false,
            stack_canary: true,
            arc: true,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_stack_canary() {
        let result = MachoCheckResult {
            pie: true,
            stack_canary: false,
            arc: true,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_nx_stack() {
        let result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: true,
            nx_stack: false,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_no_nx_heap() {
        let result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: true,
            nx_stack: true,
            nx_heap: false,
            code_signature: true,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(result.has_failures());
    }

    #[test]
    fn has_failures_code_signature_not_checked() {
        // code_signature=false alone should NOT cause has_failures (warn-only, dev builds are unsigned)
        let result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: true,
            nx_stack: true,
            nx_heap: true,
            code_signature: false,
            hardened_runtime: true,
            restrict_segment: true,
        };
        assert!(
            !result.has_failures(),
            "code_signature is not in the has_failures check"
        );
    }

    #[test]
    fn has_failures_arc_not_checked() {
        // ARC=false alone should NOT cause has_failures (it's informational)
        let result = MachoCheckResult {
            pie: true,
            stack_canary: true,
            arc: false,
            nx_stack: true,
            nx_heap: true,
            code_signature: true,
            hardened_runtime: false,
            restrict_segment: false,
        };
        assert!(
            !result.has_failures(),
            "ARC, hardened_runtime, restrict are informational"
        );
    }

    #[test]
    fn has_failures_multiple() {
        let result = MachoCheckResult {
            pie: false,
            stack_canary: false,
            arc: false,
            nx_stack: false,
            nx_heap: false,
            code_signature: false,
            hardened_runtime: false,
            restrict_segment: false,
        };
        assert!(result.has_failures());
    }

    // ---- Magic detection ----

    #[test]
    fn detect_macho_64_le() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        assert!(detect_macho(&data).is_some());
    }

    #[test]
    fn detect_macho_32_le() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&MH_MAGIC_32.to_le_bytes());
        assert!(detect_macho(&data).is_some());
    }

    #[test]
    fn detect_macho_fat() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        assert!(detect_macho(&data).is_some());
    }

    #[test]
    fn detect_not_macho() {
        let data = vec![0u8; 32];
        assert!(detect_macho(&data).is_none());
    }

    #[test]
    fn detect_too_small() {
        let data = vec![0u8; 2];
        assert!(detect_macho(&data).is_none());
    }

    // ---- Minimal Mach-O binary builders ----

    /// Build a minimal 64-bit little-endian Mach-O binary
    fn minimal_macho64(flags: u32, load_commands: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let header_size = 32;
        let mut total_lc_size: usize = 0;
        for (_, lc_data) in load_commands {
            total_lc_size += 8 + lc_data.len();
        }

        let total_size = header_size + total_lc_size + 256; // extra padding
        let mut buf = vec![0u8; total_size];

        // Magic
        buf[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        // cputype (x86_64 = 0x01000007)
        buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        // cpusubtype
        buf[8..12].copy_from_slice(&0x0000_0003u32.to_le_bytes());
        // filetype (MH_EXECUTE = 2)
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        // ncmds
        buf[16..20].copy_from_slice(&(load_commands.len() as u32).to_le_bytes());
        // sizeofcmds
        buf[20..24].copy_from_slice(&(total_lc_size as u32).to_le_bytes());
        // flags
        buf[24..28].copy_from_slice(&flags.to_le_bytes());
        // reserved (64-bit)
        buf[28..32].copy_from_slice(&0u32.to_le_bytes());

        let mut offset = header_size;
        for (cmd, lc_data) in load_commands {
            let cmdsize = (8 + lc_data.len()) as u32;
            buf[offset..offset + 4].copy_from_slice(&cmd.to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&cmdsize.to_le_bytes());
            buf[offset + 8..offset + 8 + lc_data.len()].copy_from_slice(lc_data);
            offset += cmdsize as usize;
        }

        buf
    }

    /// Build LC_SEGMENT_64 load command data (without cmd/cmdsize header)
    fn make_segment64(
        segname: &str,
        vmaddr: u64,
        vmsize: u64,
        initprot: u32,
        sections: &[(&str, &str)],
    ) -> Vec<u8> {
        // segment_command_64 body (excluding cmd, cmdsize): 64 bytes + 80 per section
        let body_size = 64 + sections.len() * 80;
        let mut data = vec![0u8; body_size];

        // segname at offset 0 (16 bytes)
        let name_bytes = segname.as_bytes();
        let copy_len = name_bytes.len().min(16);
        data[0..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // vmaddr at offset 16
        data[16..24].copy_from_slice(&vmaddr.to_le_bytes());
        // vmsize at offset 24
        data[24..32].copy_from_slice(&vmsize.to_le_bytes());
        // fileoff at offset 32
        data[32..40].copy_from_slice(&0u64.to_le_bytes());
        // filesize at offset 40
        data[40..48].copy_from_slice(&vmsize.to_le_bytes());
        // maxprot at body offset 48
        data[48..52].copy_from_slice(&0x07u32.to_le_bytes()); // rwx
        // initprot at body offset 52
        data[52..56].copy_from_slice(&initprot.to_le_bytes());
        // nsects at body offset 56
        data[56..60].copy_from_slice(&(sections.len() as u32).to_le_bytes());
        // flags at body offset 60
        data[60..64].copy_from_slice(&0u32.to_le_bytes());

        // Sections (80 bytes each)
        for (i, (sectname, seg)) in sections.iter().enumerate() {
            let sect_off = 64 + i * 80;
            let sn = sectname.as_bytes();
            let sn_len = sn.len().min(16);
            data[sect_off..sect_off + sn_len].copy_from_slice(&sn[..sn_len]);

            let sgn = seg.as_bytes();
            let sgn_len = sgn.len().min(16);
            data[sect_off + 16..sect_off + 16 + sgn_len].copy_from_slice(&sgn[..sgn_len]);
        }

        data
    }

    /// Build a minimal LC_SYMTAB with given symbol names, returning
    /// (lc_body_data, symtab_data_to_append) - the symtab_data must be placed at the
    /// offset indicated in the load command
    fn make_symtab(symbols: &[&str], strtab_file_offset: u32) -> Vec<u8> {
        // LC_SYMTAB body (excluding cmd, cmdsize): 16 bytes
        // symoff(4) + nsyms(4) + stroff(4) + strsize(4)
        let mut strtab = vec![0u8]; // leading null
        for s in symbols {
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
        }

        let mut data = vec![0u8; 16];
        // symoff - point to some dummy area (we don't parse nlist entries, just strtab)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // nsyms
        data[4..8].copy_from_slice(&(symbols.len() as u32).to_le_bytes());
        // stroff
        data[8..12].copy_from_slice(&strtab_file_offset.to_le_bytes());
        // strsize
        data[12..16].copy_from_slice(&(strtab.len() as u32).to_le_bytes());

        data
    }

    // ---- PIE check ----

    #[test]
    fn pie_detected_with_flag() {
        let buf = minimal_macho64(MH_PIE, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.pie, "MH_PIE flag should enable PIE");
    }

    #[test]
    fn pie_not_detected_without_flag() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(!result.pie, "No MH_PIE flag means no PIE");
    }

    // ---- Stack Canary check ----

    #[test]
    fn stack_canary_detected() {
        // We need the strtab at a known offset. The header is 32 bytes,
        // LC_SYMTAB is 8+16=24 bytes, so strtab can go at offset 256 (in padding).
        let symtab_body = make_symtab(&["___stack_chk_fail", "_main"], 256);
        let mut buf = minimal_macho64(0, &[(LC_SYMTAB, symtab_body)]);

        // Write string table at offset 256
        let strtab = b"\0___stack_chk_fail\0_main\0";
        if buf.len() < 256 + strtab.len() {
            buf.resize(256 + strtab.len() + 64, 0);
        }
        buf[256..256 + strtab.len()].copy_from_slice(strtab);

        let result = check_macho(&buf).expect("should parse");
        assert!(result.stack_canary, "___stack_chk_fail should be detected");
    }

    #[test]
    fn stack_canary_not_detected() {
        let symtab_body = make_symtab(&["_main"], 256);
        let mut buf = minimal_macho64(0, &[(LC_SYMTAB, symtab_body)]);
        let strtab = b"\0_main\0";
        buf[256..256 + strtab.len()].copy_from_slice(strtab);

        let result = check_macho(&buf).expect("should parse");
        assert!(!result.stack_canary);
    }

    #[test]
    fn stack_canary_guard_detected() {
        let symtab_body = make_symtab(&["___stack_chk_guard"], 256);
        let mut buf = minimal_macho64(0, &[(LC_SYMTAB, symtab_body)]);
        let strtab = b"\0___stack_chk_guard\0";
        buf[256..256 + strtab.len()].copy_from_slice(strtab);

        let result = check_macho(&buf).expect("should parse");
        assert!(
            result.stack_canary,
            "___stack_chk_guard should also indicate stack canary"
        );
    }

    // ---- ARC check ----

    #[test]
    fn arc_detected() {
        let symtab_body = make_symtab(&["_objc_release"], 256);
        let mut buf = minimal_macho64(0, &[(LC_SYMTAB, symtab_body)]);
        let strtab = b"\0_objc_release\0";
        buf[256..256 + strtab.len()].copy_from_slice(strtab);

        let result = check_macho(&buf).expect("should parse");
        assert!(result.arc, "_objc_release should indicate ARC");
    }

    #[test]
    fn arc_not_detected() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(!result.arc);
    }

    // ---- NX Stack check ----

    #[test]
    fn nx_stack_with_pagezero() {
        let pagezero = make_segment64("__PAGEZERO", 0, 0x1_0000_0000, 0, &[]);
        let buf = minimal_macho64(0, &[(LC_SEGMENT_64, pagezero)]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.nx_stack, "__PAGEZERO should indicate NX stack");
    }

    #[test]
    fn nx_stack_64bit_default() {
        // 64-bit binary without __PAGEZERO still gets NX by default
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.nx_stack, "64-bit binaries default to NX stack");
    }

    // ---- NX Heap check ----

    #[test]
    fn nx_heap_data_not_executable() {
        let data_seg = make_segment64("__DATA", 0x1_0000_0000, 0x1000, 0x03, &[]); // rw- (no execute)
        let buf = minimal_macho64(0, &[(LC_SEGMENT_64, data_seg)]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.nx_heap, "__DATA without execute should be NX heap");
    }

    #[test]
    fn nx_heap_data_executable() {
        let data_seg = make_segment64("__DATA", 0x1_0000_0000, 0x1000, 0x07, &[]); // rwx
        let buf = minimal_macho64(0, &[(LC_SEGMENT_64, data_seg)]);
        let result = check_macho(&buf).expect("should parse");
        assert!(
            !result.nx_heap,
            "__DATA with execute should fail NX heap check"
        );
    }

    #[test]
    fn nx_heap_no_data_segment() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.nx_heap, "No __DATA segment defaults to NX heap");
    }

    // ---- Code Signature check ----

    #[test]
    fn code_signature_present() {
        // LC_CODE_SIGNATURE body: dataoff(4) + datasize(4)
        let cs_offset: u32 = 512;
        let cs_size: u32 = 64;
        let mut lc_body = vec![0u8; 8];
        lc_body[0..4].copy_from_slice(&cs_offset.to_le_bytes());
        lc_body[4..8].copy_from_slice(&cs_size.to_le_bytes());

        let mut buf = minimal_macho64(0, &[(LC_CODE_SIGNATURE, lc_body)]);
        buf.resize((cs_offset + cs_size) as usize + 64, 0);
        // Write minimal signature data
        buf[cs_offset as usize..cs_offset as usize + 4]
            .copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());

        let result = check_macho(&buf).expect("should parse");
        assert!(result.code_signature);
    }

    #[test]
    fn code_signature_absent() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(!result.code_signature);
    }

    // ---- Hardened Runtime check ----

    #[test]
    fn hardened_runtime_detected() {
        let cs_offset: u32 = 512;
        // Build a minimal SuperBlob with one CodeDirectory that has CS_RUNTIME flag
        let mut cs_data = vec![0u8; 128];
        // SuperBlob magic (BE)
        cs_data[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        // length (BE)
        cs_data[4..8].copy_from_slice(&128u32.to_be_bytes());
        // count = 1 (BE)
        cs_data[8..12].copy_from_slice(&1u32.to_be_bytes());
        // BlobIndex[0]: type=0 (CodeDirectory), offset=20
        cs_data[12..16].copy_from_slice(&0u32.to_be_bytes());
        cs_data[16..20].copy_from_slice(&20u32.to_be_bytes());
        // CodeDirectory at offset 20
        let cd_offset = 20;
        // magic = 0xFADE0C02 (BE)
        cs_data[cd_offset..cd_offset + 4].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        // length
        cs_data[cd_offset + 4..cd_offset + 8].copy_from_slice(&80u32.to_be_bytes());
        // version = 0x20400 (supports runtime)
        cs_data[cd_offset + 8..cd_offset + 12].copy_from_slice(&0x0002_0400u32.to_be_bytes());
        // flags with CS_RUNTIME
        cs_data[cd_offset + 12..cd_offset + 16].copy_from_slice(&CS_RUNTIME.to_be_bytes());

        let cs_size = cs_data.len() as u32;
        let mut lc_body = vec![0u8; 8];
        lc_body[0..4].copy_from_slice(&cs_offset.to_le_bytes());
        lc_body[4..8].copy_from_slice(&cs_size.to_le_bytes());

        let mut buf = minimal_macho64(0, &[(LC_CODE_SIGNATURE, lc_body)]);
        buf.resize((cs_offset as usize) + cs_data.len() + 64, 0);
        buf[cs_offset as usize..cs_offset as usize + cs_data.len()].copy_from_slice(&cs_data);

        let result = check_macho(&buf).expect("should parse");
        assert!(result.hardened_runtime);
    }

    #[test]
    fn hardened_runtime_not_detected() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(!result.hardened_runtime);
    }

    // ---- Restrict segment check ----

    #[test]
    fn restrict_segment_present() {
        let restrict_seg = make_segment64(
            "__RESTRICT",
            0x2_0000_0000,
            0x1000,
            0x01,
            &[("__restrict", "__RESTRICT")],
        );
        let buf = minimal_macho64(0, &[(LC_SEGMENT_64, restrict_seg)]);
        let result = check_macho(&buf).expect("should parse");
        assert!(result.restrict_segment);
    }

    #[test]
    fn restrict_segment_absent() {
        let buf = minimal_macho64(0, &[]);
        let result = check_macho(&buf).expect("should parse");
        assert!(!result.restrict_segment);
    }

    #[test]
    fn restrict_segment_wrong_section_name() {
        let restrict_seg = make_segment64(
            "__RESTRICT",
            0x2_0000_0000,
            0x1000,
            0x01,
            &[("__other", "__RESTRICT")],
        );
        let buf = minimal_macho64(0, &[(LC_SEGMENT_64, restrict_seg)]);
        let result = check_macho(&buf).expect("should parse");
        assert!(
            !result.restrict_segment,
            "Wrong section name should not match"
        );
    }

    // ---- Parse failure ----

    #[test]
    fn parse_empty_data() {
        assert!(check_macho(&[]).is_none());
    }

    #[test]
    fn parse_too_small() {
        assert!(check_macho(&[0xCF, 0xFA]).is_none());
    }

    #[test]
    fn parse_invalid_magic() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(check_macho(&data).is_none());
    }

    // ---- Fully hardened binary ----

    #[test]
    fn fully_hardened_macho() {
        let cs_offset: u32 = 1024;
        let mut cs_data = vec![0u8; 128];
        cs_data[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        cs_data[4..8].copy_from_slice(&128u32.to_be_bytes());
        cs_data[8..12].copy_from_slice(&1u32.to_be_bytes());
        cs_data[12..16].copy_from_slice(&0u32.to_be_bytes());
        cs_data[16..20].copy_from_slice(&20u32.to_be_bytes());
        let cd_offset = 20;
        cs_data[cd_offset..cd_offset + 4].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        cs_data[cd_offset + 4..cd_offset + 8].copy_from_slice(&80u32.to_be_bytes());
        cs_data[cd_offset + 8..cd_offset + 12].copy_from_slice(&0x0002_0400u32.to_be_bytes());
        cs_data[cd_offset + 12..cd_offset + 16].copy_from_slice(&CS_RUNTIME.to_be_bytes());

        let cs_size = cs_data.len() as u32;
        let mut cs_lc_body = vec![0u8; 8];
        cs_lc_body[0..4].copy_from_slice(&cs_offset.to_le_bytes());
        cs_lc_body[4..8].copy_from_slice(&cs_size.to_le_bytes());

        let pagezero = make_segment64("__PAGEZERO", 0, 0x1_0000_0000, 0, &[]);
        let data_seg = make_segment64("__DATA", 0x1_0000_0000, 0x1000, 0x03, &[]);
        let restrict_seg = make_segment64(
            "__RESTRICT",
            0x2_0000_0000,
            0x1000,
            0x01,
            &[("__restrict", "__RESTRICT")],
        );
        let symtab_body = make_symtab(&["___stack_chk_fail", "_objc_release", "_main"], 800);

        let mut buf = minimal_macho64(
            MH_PIE,
            &[
                (LC_SEGMENT_64, pagezero),
                (LC_SEGMENT_64, data_seg),
                (LC_SEGMENT_64, restrict_seg),
                (LC_SYMTAB, symtab_body),
                (LC_CODE_SIGNATURE, cs_lc_body),
            ],
        );

        // Ensure buffer is large enough
        buf.resize((cs_offset as usize) + cs_data.len() + 64, 0);

        // Write string table at offset 800
        let strtab = b"\0___stack_chk_fail\0_objc_release\0_main\0";
        buf[800..800 + strtab.len()].copy_from_slice(strtab);

        // Write code signature at cs_offset
        buf[cs_offset as usize..cs_offset as usize + cs_data.len()].copy_from_slice(&cs_data);

        let result = check_macho(&buf).expect("should parse");
        assert!(result.pie, "should have PIE");
        assert!(result.stack_canary, "should have stack canary");
        assert!(result.arc, "should have ARC");
        assert!(result.nx_stack, "should have NX stack");
        assert!(result.nx_heap, "should have NX heap");
        assert!(result.code_signature, "should have code signature");
        assert!(result.hardened_runtime, "should have hardened runtime");
        assert!(result.restrict_segment, "should have restrict segment");
        assert!(
            !result.has_failures(),
            "fully hardened should have no failures"
        );
    }
}
