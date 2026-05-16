# bincheck verified binaries

- **bincheck version**: `0.3.1`
- **Verification date (JST)**: 2026-05-16
- **Verification host**: Linux 6.6.87.2-microsoft-standard-WSL2 x86_64

This document is **regenerated** by `scripts/verify-external.sh` from
`tests/external/manifest.toml` and the live bincheck output. Do not
edit by hand — re-run the script and commit the result.

## Entries

### busybox 1.35.0 (x86_64-musl)
- **License (upstream)**: GPL-2.0-only
- **URL**: https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
- **SHA-256**: `6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348`
- **Detected libc flavor**: none
- **Banned functions detected**: none

### curl 8.7.1 (aarch64-musl)
- **License (upstream)**: curl
- **URL**: https://github.com/stunnel/static-curl/releases/download/8.7.1/curl-linux-aarch64-musl-8.7.1.tar.xz
- **SHA-256**: `9f93fec379543d6935667bbf7d50119ad326b2f5564240291e5904b62d03a4ac`
- **Detected libc flavor**: none
- **Banned functions detected**: none
- **Notes**: Tarball; verify-external.sh extracts the inner `curl` ELF before checking.

### wget 1.21.3-1+deb12u1 (x86_64-glibc)
- **License (upstream)**: GPL-3.0-or-later
- **URL**: https://deb.debian.org/debian/pool/main/w/wget/wget_1.21.3-1+deb12u1_amd64.deb
- **SHA-256**: `b389052d1d8a8cacec4f0380d9ee54e8082bfbebe374299be95b5286c9380f80`
- **Detected libc flavor**: glibc
- **Banned functions detected**: strcpy, sprintf

### coreutils-ls 9.1-1 (x86_64-glibc)
- **License (upstream)**: GPL-3.0-or-later
- **URL**: https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.1-1_amd64.deb
- **SHA-256**: `61038f857e346e8500adf53a2a0a20859f4d3a3b51570cc876b153a2d51a3091`
- **Detected libc flavor**: glibc
- **Banned functions detected**: strcpy
- **Notes**: Used as the canonical glibc + fortify reference (expect __*_chk variants present).


---

All product, project, and distribution names mentioned in this document are trademarks or registered
trademarks of their respective owners. They are used here solely for
descriptive identification of test targets and do not imply endorsement,
sponsorship, or affiliation.
