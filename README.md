# bincheck

[![CI](https://github.com/kazu11max17/bincheck/actions/workflows/ci.yml/badge.svg)](https://github.com/kazu11max17/bincheck/actions)
[![Crates.io](https://img.shields.io/crates/v/bincheck.svg)](https://crates.io/crates/bincheck)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Fast binary security property checker for ELF, PE, and Mach-O files.

Inspect hardening features (RELRO, Stack Canary, NX, PIE, ASLR, DEP, CFG, etc.) in a single command.

## Install

```bash
cargo install bincheck
```

Or build from source:

```bash
git clone https://github.com/kazu11max17/bincheck.git
cd bincheck
cargo build --release
```

## Quick Start

```bash
# Check a binary
bincheck /usr/bin/ls

# Check multiple binaries
bincheck /usr/bin/ls /usr/bin/cat /usr/bin/grep

# JSON output (for scripting)
bincheck -f json /usr/bin/ls

# SARIF output (for CI integration)
bincheck -f sarif /usr/bin/ls

# Fail CI if any check fails
bincheck --strict /usr/bin/ls
```

## Example Output

```
File: /usr/bin/ls (ELF)
┌────────────────┬────────┬──────────────────────┐
│ Property       ┆ Status ┆ Details              │
╞════════════════╪════════╪══════════════════════╡
│ RELRO          ┆ PASS   ┆ Full                 │
├────────────────┼────────┼──────────────────────┤
│ Stack Canary   ┆ PASS   ┆ __stack_chk_fail     │
├────────────────┼────────┼──────────────────────┤
│ NX             ┆ PASS   ┆ Stack not executable │
├────────────────┼────────┼──────────────────────┤
│ PIE            ┆ PASS   ┆ ET_DYN               │
├────────────────┼────────┼──────────────────────┤
│ Fortify Source ┆ PASS   ┆ __printf_chk         │
├────────────────┼────────┼──────────────────────┤
│ RPATH          ┆ PASS   ┆ Not set              │
├────────────────┼────────┼──────────────────────┤
│ RUNPATH        ┆ PASS   ┆ Not set              │
└────────────────┴────────┴──────────────────────┘
```

## Security Checks

### ELF Binaries

| Check | What it detects |
|-------|----------------|
| RELRO | GOT protection level (Full / Partial / None) |
| Stack Canary | `__stack_chk_fail` in dynamic or static symbols |
| NX | Non-executable stack (W^X) |
| PIE | Position Independent Executable (ASLR support) |
| Fortify Source | Fortified libc functions (`__*_chk`) |
| RPATH/RUNPATH | Hardcoded library search paths (supply chain risk) |
| Linkage | `dynamic` / `static` / `static-pie` classification (informational) |
| File Mode (SUID/SGID) | `04000` / `02000` mode bits (informational; `--strict` promotes to failure) |

### PE Binaries (Windows)

| Check | What it detects |
|-------|----------------|
| ASLR | Address Space Layout Randomization (`DYNAMIC_BASE`) |
| High Entropy ASLR | 64-bit ASLR (`HIGH_ENTROPY_VA`) |
| DEP/NX | Data Execution Prevention (`NX_COMPAT`) |
| CFG | Control Flow Guard (`GUARD_CF`) |
| SafeSEH | Structured Exception Handling protection |
| Authenticode | Code signing (Certificate Table present) |

### Mach-O Binaries (macOS)

| Check | What it detects |
|-------|----------------|
| PIE | Position Independent Executable (`MH_PIE` flag) |
| Stack Canary | `__stack_chk_fail` in symbol table |
| NX Stack | Non-executable stack segment |
| NX Heap | Non-executable heap segment |
| Code Signature | Embedded code signature (`LC_CODE_SIGNATURE`) |
| Hardened Runtime | Hardened runtime enabled (`CS_RUNTIME` flag) |
| ARC | Automatic Reference Counting (`_objc_release` present) — memory management aid, reduces use-after-free risk |
| Restrict Segment | `__RESTRICT,__restrict` segment present (legacy dyld injection guard; superseded by Hardened Runtime on modern macOS) |

## Output Formats

- **table** (default) — Color-coded terminal output
- **json** — Machine-readable JSON
- **sarif** — [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning and CI tools

## GitHub Action

```yaml
- uses: kazu11max17/bincheck@v0.3.0
  with:
    files: target/release/myapp
```

With SARIF upload to GitHub Code Scanning:

```yaml
- uses: kazu11max17/bincheck@v0.3.0
  with:
    files: target/release/myapp
    format: sarif
    strict: true
    sarif-upload: true
```

| Input | Description | Default |
|-------|-------------|---------|
| `files` | Space-separated binary paths (required) | |
| `format` | `table`, `json`, or `sarif` | `table` |
| `strict` | Exit 1 if any check fails | `false` |
| `version` | bincheck version to install | latest |
| `sarif-upload` | Upload SARIF to Code Scanning | `false` |

## Check Reference

### SUID-SGID

bincheck reports the SUID (`04000`) and SGID (`02000`) bits of the file passed on
the command line. Detection happens at the file layer via `symlink_metadata`, so
the bits reflect the entry the user named — symlinks are reported as `symlink`
without following them. By default the SUID/SGID row is informational (`WARN` in
the table, `note` in SARIF). With `--strict`, an SUID or SGID file causes
bincheck to exit `1` so it can gate a CI pipeline.

The check is Unix-only; on Windows it reports `not_applicable`.

### Static-PIE

bincheck classifies an ELF as one of `dynamic` / `static` / `static-pie`:

- **dynamic** — `PT_INTERP` is present (regular dynamically linked executable).
- **static** — `ET_EXEC` with no `PT_INTERP` and no `DT_NEEDED`.
- **static-pie** — `ET_DYN` with no `PT_INTERP`, no `DT_NEEDED`, `e_entry != 0`,
  and `PT_DYNAMIC` present. `DT_FLAGS_1 & DF_1_PIE` is treated as a confirming
  signal when emitted by the linker, but its absence does not override the
  classification (not every toolchain emits it).

Linkage is informational only. The existing `PIE` check still flags the
underlying `ET_DYN` requirement independently.

## Security Model

bincheck is designed for **CI / build-time inspection of artifacts produced by
your own pipeline**. The threat model assumes the binary path is under the
caller's control and the surrounding directory is not attacker-writable.

A few consequences worth being explicit about:

- **TOCTOU on file-mode**: the SUID/SGID check (`symlink_metadata`) and the
  binary parse (`fs::read`) are two separate syscalls. If the path is in a
  directory where an attacker can swap entries between those calls, the
  reported file-mode and the parsed binary contents may not refer to the same
  inode. Run bincheck against artifacts staged in a directory you own.
- **PIE is a single-condition check**: the `PIE` row reports `ET_DYN` only.
  The `Linkage` row applies the multi-condition heuristic for `static-pie`. A
  hand-crafted ELF with `ET_DYN` set but no `PT_DYNAMIC` will still pass `PIE`
  while showing `Linkage: unknown`.
- **No code execution**: bincheck never executes the inspected binary, so
  malicious payloads inside an inspected artifact are not invoked. Parsing is
  delegated to [`goblin`](https://crates.io/crates/goblin).

If you need stricter guarantees (e.g. inspecting untrusted uploads), invoke
bincheck against a path you `mv`-into-place yourself and confirm the result
applies to that exact inode out-of-band.

## Use Cases

- **CI/CD pipelines**: Use `--strict --format sarif` to gate releases on binary hardening
- **Firmware audits**: Check embedded Linux binaries for missing protections
- **Supply chain security**: Verify third-party binaries before deployment
- **Compliance**: Document security properties for regulatory requirements

## Roadmap

- **v0.3.0** (current) — File Mode (SUID/SGID) detection, Static-PIE / Static / Dynamic linkage classification
- **v0.3.x** — Banned function detection (`gets`/`strcpy`/`system` etc.), libc flavor identification (glibc/musl/uclibc/bionic)
- **v0.4.0** — CET / BTI / PAC checks via `NT_GNU_PROPERTY_TYPE_0` (x86_64 IBT/SHSTK, AArch64 BTI/PAC)

## License

Apache-2.0