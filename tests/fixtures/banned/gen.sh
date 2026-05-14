#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# F1 (BHC010) + F5 (BHC014) fixture generator.
#
# Run on a Linux build host with at least `gcc`. Optional toolchains
# (`aarch64-linux-gnu-gcc`, `musl-gcc`) extend the cross-arch / cross-libc
# coverage; they are skipped silently when missing.
#
# Output ELFs land next to this script and are committed to the repo so CI
# does not need a build toolchain. Re-run only when the C sources below change.
#
# All emitted binaries derive from C sources written by the bincheck authors;
# no third-party code is bundled.

set -eu
cd "$(dirname "$0")"

# --- danger.c: HIGH severity banned functions ---
cat > /tmp/bincheck-danger.c <<'EOF'
/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc < 2) return 1;
    strcpy(buf, argv[1]);
    sprintf(buf, "%s", argv[1]);
    system(argv[1]);
    return 0;
}
EOF

gcc -O0 -no-pie /tmp/bincheck-danger.c -o danger-x86_64-unfortified
gcc -O2 -D_FORTIFY_SOURCE=2 /tmp/bincheck-danger.c -o danger-x86_64-fortified-glibc

if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    aarch64-linux-gnu-gcc /tmp/bincheck-danger.c -o danger-aarch64-glibc
else
    echo "skip: aarch64-linux-gnu-gcc not installed"
fi

if command -v musl-gcc >/dev/null 2>&1; then
    musl-gcc /tmp/bincheck-danger.c -o danger-x86_64-musl
else
    echo "skip: musl-gcc not installed"
fi

# --- safe.c: no banned functions ---
cat > /tmp/bincheck-safe.c <<'EOF'
/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc < 2) return 1;
    strncpy(buf, argv[1], sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    return 0;
}
EOF
gcc /tmp/bincheck-safe.c -o safe-x86_64

rm -f /tmp/bincheck-danger.c /tmp/bincheck-safe.c
echo ""
echo "Generated fixtures in $(pwd):"
ls -la danger-* safe-* 2>/dev/null || true
