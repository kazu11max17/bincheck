//! F5 (BHC014): libc flavor detection.
//!
//! Best-effort heuristic that classifies which libc implementation a Linux ELF
//! depends on. Primary signal is `DT_NEEDED` strings; `.comment` is consulted
//! as a tie-breaker (best-effort: stripped binaries lose `.comment`).
//!
//! Per spec §F5: this is **not** a security signal on its own. F1's fortify
//! suppression keys off `Glibc` only; everything else (`Musl` / `Uclibc` /
//! `Bionic` / `None` / `Unknown`) leaves suppression off (fail-safe). Threat
//! model: an attacker who forges `DT_NEEDED` cannot trick us into hiding a
//! banned symbol because suppression requires a *positive* `Glibc` decision
//! and we degrade to `Unknown` on any conflict.

use goblin::elf::Elf;
use goblin::elf::dynamic::DT_NEEDED;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LibcFlavor {
    Glibc,
    Musl,
    Uclibc,
    Bionic,
    /// Static binary: no `DT_NEEDED` entries at all.
    None,
    Unknown,
}

impl std::fmt::Display for LibcFlavor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LibcFlavor::Glibc => write!(f, "glibc"),
            LibcFlavor::Musl => write!(f, "musl"),
            LibcFlavor::Uclibc => write!(f, "uclibc"),
            LibcFlavor::Bionic => write!(f, "bionic"),
            LibcFlavor::None => write!(f, "none"),
            LibcFlavor::Unknown => write!(f, "unknown"),
        }
    }
}

/// Classify a `DT_NEEDED` string. Returns `None` when the string carries no
/// libc signal (e.g. `libssl.so.1.1`).
fn classify_needed(name: &str) -> Option<LibcFlavor> {
    // glibc: `libc.so.6`, sometimes `ld-linux*.so.2`
    if name == "libc.so.6" || name.starts_with("ld-linux") {
        return Some(LibcFlavor::Glibc);
    }
    // musl: `libc.musl-x86_64.so.1`, `ld-musl-*.so.1`
    if name.starts_with("libc.musl-") || name.starts_with("ld-musl-") {
        return Some(LibcFlavor::Musl);
    }
    // uclibc / uclibc-ng: `libc.so.0`, `ld-uClibc.so.0`
    if name == "libc.so.0" || name.starts_with("ld-uClibc") || name.starts_with("libuClibc") {
        return Some(LibcFlavor::Uclibc);
    }
    // bionic (Android): the dynamic linker is `linker` (32-bit) / `linker64`.
    // `libc.so` alone is ambiguous (musl also uses it on some distros) so we
    // only commit to bionic when the Android linker is named.
    if name == "linker" || name == "linker64" {
        return Some(LibcFlavor::Bionic);
    }
    None
}

/// Best-effort classification from `.comment` strings. Returns `None` when no
/// recognisable token is present (typical for stripped binaries).
fn classify_comment(comment: &str) -> Option<LibcFlavor> {
    let lower = comment.to_ascii_lowercase();
    if lower.contains("musl") {
        return Some(LibcFlavor::Musl);
    }
    if lower.contains("uclibc") {
        return Some(LibcFlavor::Uclibc);
    }
    if lower.contains("bionic") || lower.contains("android clang") {
        return Some(LibcFlavor::Bionic);
    }
    // glibc-built objects usually carry "GCC: (GNU)" without an explicit
    // "glibc" token. We deliberately do **not** infer glibc from a bare GCC
    // banner because cross-toolchains print it too. Leave glibc inference to
    // the `DT_NEEDED` side.
    if lower.contains("glibc") {
        return Some(LibcFlavor::Glibc);
    }
    None
}

/// F5 entry point. Combines `DT_NEEDED` classification with optional
/// `.comment` votes (when bytes are available via [`detect_libc_flavor_with_comment`]).
pub fn detect_libc_flavor(elf: &Elf) -> LibcFlavor {
    detect_libc_flavor_with_comment(elf, None)
}

/// Variant that also takes the raw ELF bytes so we can read `.comment` for the
/// majority vote. Callers that already have the file contents (e.g. `check_file`)
/// should prefer this. When `bytes` is `None` we skip the `.comment` heuristic.
pub fn detect_libc_flavor_with_comment(elf: &Elf, bytes: Option<&[u8]>) -> LibcFlavor {
    // Collect votes from DT_NEEDED.
    let mut needed_votes: Vec<LibcFlavor> = Vec::new();
    let mut needed_count = 0usize;
    if let Some(ref dynamic) = elf.dynamic {
        for d in &dynamic.dyns {
            if d.d_tag != DT_NEEDED {
                continue;
            }
            needed_count += 1;
            if let Some(name) = elf.dynstrtab.get_at(d.d_val as usize)
                && let Some(flavor) = classify_needed(name)
            {
                needed_votes.push(flavor);
            }
        }
    }

    // Static binary fast path.
    if needed_count == 0 {
        // Even fully static; .comment can still hint at musl (common on
        // BusyBox musl-static) but we classify via `.comment` only.
        if let Some(b) = bytes
            && let Some(c) = read_comment_bytes(elf, b)
            && let Some(f) = classify_comment(&c)
        {
            return f;
        }
        return LibcFlavor::None;
    }

    // Tally DT_NEEDED votes.
    let mut dt_choice: Option<LibcFlavor> = None;
    if !needed_votes.is_empty() {
        let first = needed_votes[0];
        if needed_votes.iter().all(|v| *v == first) {
            dt_choice = Some(first);
        } else {
            // Conflicting flavors in DT_NEEDED → treat as adversarial / unknown.
            return LibcFlavor::Unknown;
        }
    }

    // Comment vote (best-effort).
    let mut comment_choice: Option<LibcFlavor> = None;
    if let Some(b) = bytes
        && let Some(c) = read_comment_bytes(elf, b)
    {
        comment_choice = classify_comment(&c);
    }
    match (dt_choice, comment_choice) {
        (Some(a), Some(b)) if a == b => a,
        (Some(a), Some(_b)) => {
            // DT_NEEDED says one thing, .comment says another. Per spec §F5
            // fail-safe: degrade to Unknown so F1 fortify suppression stays off.
            // Exception: a glibc DT_NEEDED + glibc-compatible .comment is
            // already covered by the equality arm. A bare GCC banner returns
            // None from classify_comment so it never reaches here.
            let _ = a;
            LibcFlavor::Unknown
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => LibcFlavor::Unknown,
    }
}

/// Read `.comment` from raw ELF bytes (best-effort). Returns `None` when the
/// section is missing, out of bounds, or not valid UTF-8.
fn read_comment_bytes(elf: &Elf, bytes: &[u8]) -> Option<String> {
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name)?;
        if name != ".comment" {
            continue;
        }
        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        let end = offset.checked_add(size)?;
        if end > bytes.len() {
            return None;
        }
        let raw = &bytes[offset..end];
        // .comment is a sequence of NUL-terminated strings; concatenate with
        // spaces for the heuristic.
        let mut out = String::new();
        for chunk in raw.split(|b| *b == 0) {
            if let Ok(s) = std::str::from_utf8(chunk)
                && !s.is_empty()
            {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(s);
            }
        }
        if out.is_empty() {
            return None;
        }
        return Some(out);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_needed_glibc() {
        assert_eq!(classify_needed("libc.so.6"), Some(LibcFlavor::Glibc));
        assert_eq!(
            classify_needed("ld-linux-x86-64.so.2"),
            Some(LibcFlavor::Glibc)
        );
    }

    #[test]
    fn classify_needed_musl() {
        assert_eq!(
            classify_needed("libc.musl-x86_64.so.1"),
            Some(LibcFlavor::Musl)
        );
        assert_eq!(
            classify_needed("ld-musl-aarch64.so.1"),
            Some(LibcFlavor::Musl)
        );
    }

    #[test]
    fn classify_needed_uclibc() {
        assert_eq!(classify_needed("libc.so.0"), Some(LibcFlavor::Uclibc));
        assert_eq!(classify_needed("ld-uClibc.so.0"), Some(LibcFlavor::Uclibc));
    }

    #[test]
    fn classify_needed_bionic() {
        assert_eq!(classify_needed("linker"), Some(LibcFlavor::Bionic));
        assert_eq!(classify_needed("linker64"), Some(LibcFlavor::Bionic));
    }

    #[test]
    fn classify_needed_unrecognised() {
        assert_eq!(classify_needed("libssl.so.1.1"), None);
        assert_eq!(classify_needed("libpthread.so.0"), None);
    }

    #[test]
    fn classify_comment_musl() {
        assert_eq!(
            classify_comment("musl libc (x86_64) 1.2.4"),
            Some(LibcFlavor::Musl)
        );
    }

    #[test]
    fn classify_comment_glibc() {
        assert_eq!(
            classify_comment("GLIBC_2.34 something"),
            Some(LibcFlavor::Glibc)
        );
    }

    #[test]
    fn classify_comment_bare_gcc_is_none() {
        assert_eq!(classify_comment("GCC: (GNU) 13.2.0"), None);
    }

    #[test]
    fn libc_flavor_serializes_lowercase() {
        let json = serde_json::to_string(&LibcFlavor::Musl).unwrap();
        assert_eq!(json, "\"musl\"");
        let json = serde_json::to_string(&LibcFlavor::None).unwrap();
        assert_eq!(json, "\"none\"");
    }

    #[test]
    fn libc_flavor_display() {
        assert_eq!(LibcFlavor::Glibc.to_string(), "glibc");
        assert_eq!(LibcFlavor::Musl.to_string(), "musl");
        assert_eq!(LibcFlavor::Uclibc.to_string(), "uclibc");
        assert_eq!(LibcFlavor::Bionic.to_string(), "bionic");
        assert_eq!(LibcFlavor::None.to_string(), "none");
        assert_eq!(LibcFlavor::Unknown.to_string(), "unknown");
    }
}
