# F1 / F5 fixtures (BHC010 / BHC014)

This directory holds **self-generated** ELF fixtures used to exercise
banned-function detection (F1) and libc flavor identification (F5).

All ELFs in this directory are produced from C sources embedded in
`gen.sh`; no third-party binaries are committed.

## License

`SPDX-License-Identifier: Apache-2.0`

The C sources and the generator script are authored by the bincheck
project and licensed under Apache-2.0, matching the repository.

## Regenerate

Requires a Linux build host with `gcc`. Optional cross/alt-libc
toolchains extend coverage:

- `aarch64-linux-gnu-gcc` (Debian package `gcc-aarch64-linux-gnu`)
- `musl-gcc` (Debian package `musl-tools`)

```sh
cd tests/fixtures/banned
./gen.sh
```

Re-run only when the C sources in `gen.sh` change. The generated ELFs
are committed so CI does not need a toolchain.

## File inventory

| File | Purpose |
|------|---------|
| `danger-x86_64-unfortified` | x86_64 glibc, `-no-pie`, no `_FORTIFY_SOURCE`. Expect HIGH detections for `strcpy`, `sprintf`, `system`. |
| `danger-x86_64-fortified-glibc` | x86_64 glibc, `-O2 -D_FORTIFY_SOURCE=2`. Expect `__sprintf_chk`/`__strcpy_chk`; bare `sprintf`/`strcpy` should be **suppressed** (glibc-only gate). |
| `danger-aarch64-glibc` | aarch64 glibc cross-build. Same banned-function profile as x86_64. Optional. |
| `danger-x86_64-musl` | x86_64 musl static. Expect HIGH detections; `_chk` suppression must NOT apply (spec §F1 L83). Optional. |
| `safe-x86_64` | x86_64 glibc with no banned functions. Negative control. |

## CI integration

These fixtures are **not** wired into `cargo test` automatically; the
manifest plumbing lives under `tests/external/` and is manually run via
`scripts/verify-external.sh` before each release. Adding a `cargo test`
suite that consumes these binaries is left for v0.4.x once the manifest
expected-result schema is stable (Nao's responsibility).
