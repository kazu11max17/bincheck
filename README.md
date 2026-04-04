# bincheck

[![CI](https://github.com/kazu11max17/bincheck/actions/workflows/ci.yml/badge.svg)](https://github.com/kazu11max17/bincheck/actions)
[![Crates.io](https://img.shields.io/crates/v/bincheck.svg)](https://crates.io/crates/bincheck)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Fast binary security property checker for ELF and PE files.

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
│ RELRO          ┆ ✓ Pass ┆ Full                 │
├────────────────┼────────┼──────────────────────┤
│ Stack Canary   ┆ ✓ Pass ┆ __stack_chk_fail     │
├────────────────┼────────┼──────────────────────┤
│ NX             ┆ ✓ Pass ┆ Stack not executable │
├────────────────┼────────┼──────────────────────┤
│ PIE            ┆ ✓ Pass ┆ ET_DYN               │
├────────────────┼────────┼──────────────────────┤
│ Fortify Source ┆ ✓ Pass ┆ __printf_chk          │
├────────────────┼────────┼──────────────────────┤
│ RPATH          ┆ ✓ Pass ┆ Not set              │
├────────────────┼────────┼──────────────────────┤
│ RUNPATH        ┆ ✓ Pass ┆ Not set              │
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

### PE Binaries (Windows)

| Check | What it detects |
|-------|----------------|
| ASLR | Address Space Layout Randomization (`DYNAMIC_BASE`) |
| High Entropy ASLR | 64-bit ASLR (`HIGH_ENTROPY_VA`) |
| DEP/NX | Data Execution Prevention (`NX_COMPAT`) |
| CFG | Control Flow Guard (`GUARD_CF`) |
| SafeSEH | Structured Exception Handling protection |
| Authenticode | Code signing (Certificate Table present) |

## Output Formats

- **table** (default) — Color-coded terminal output
- **json** — Machine-readable JSON
- **sarif** — [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning and CI tools

## GitHub Action

```yaml
- uses: kazu11max17/bincheck@v0.1.0
  with:
    files: target/release/myapp
```

With SARIF upload to GitHub Code Scanning:

```yaml
- uses: kazu11max17/bincheck@v0.1.0
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

## Use Cases

- **CI/CD pipelines**: Use `--strict --format sarif` to gate releases on binary hardening
- **Firmware audits**: Check embedded Linux binaries for missing protections
- **Supply chain security**: Verify third-party binaries before deployment
- **Compliance**: Document security properties for regulatory requirements

## License

Apache-2.0