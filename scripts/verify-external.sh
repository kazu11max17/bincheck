#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Pre-release manual verification driver.
#
# Reads tests/external/manifest.toml, downloads each binary into
# tests/external/downloads/ (gitignored), verifies SHA-256, runs `bincheck
# --format json`, diffs the result against tests/external/expected/, and
# regenerates docs/verified-binaries.md from the live observations.
#
# Dependencies (must be on PATH):
#   bash 4+, curl, sha256sum, jq, python3 (>=3.11 for tomllib),
#   tar, ar (for .deb extraction), cargo
#
# Exit codes:
#   0 = all entries verified, doc regenerated
#   1 = at least one verification failed
#   2 = environment/setup error (missing tool, malformed manifest)

set -euo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$REPO_ROOT/tests/external/manifest.toml"
DOWNLOADS="$REPO_ROOT/tests/external/downloads"
EXPECTED_DIR="$REPO_ROOT/tests/external/expected"
DOC_OUT="$REPO_ROOT/docs/verified-binaries.md"

mkdir -p "$DOWNLOADS"
mkdir -p "$(dirname "$DOC_OUT")"

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required tool '$1' not on PATH" >&2
        exit 2
    }
}
for t in curl sha256sum jq python3 tar ar cargo; do require "$t"; done

if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: manifest not found: $MANIFEST" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Build bincheck (release)
# ---------------------------------------------------------------------------

echo "==> Building bincheck (release)"
( cd "$REPO_ROOT" && cargo build --release --quiet )
BINCHECK="$REPO_ROOT/target/release/bincheck"
BINCHECK_VERSION="$("$BINCHECK" --version | awk '{print $2}')"
echo "    bincheck version: $BINCHECK_VERSION"

# ---------------------------------------------------------------------------
# Parse manifest with python3 + tomllib (no extra Rust dep)
# ---------------------------------------------------------------------------

ENTRIES_JSON="$(python3 - "$MANIFEST" <<'PY'
import json, sys, tomllib
with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)
print(json.dumps(data.get("binary", [])))
PY
)"
ENTRY_COUNT="$(echo "$ENTRIES_JSON" | jq 'length')"
echo "==> Manifest entries: $ENTRY_COUNT"

# ---------------------------------------------------------------------------
# Per-entry verification
# ---------------------------------------------------------------------------

declare -a SUMMARY=()
OVERALL_FAIL=0
DOC_ENTRIES_JSON="[]"

verify_one() {
    local idx="$1"
    local entry; entry="$(echo "$ENTRIES_JSON" | jq ".[$idx]")"
    local name; name=$(echo "$entry" | jq -r '.name')
    local version; version=$(echo "$entry" | jq -r '.version')
    local arch; arch=$(echo "$entry" | jq -r '.arch')
    local url; url=$(echo "$entry" | jq -r '.url')
    local sha_expected; sha_expected=$(echo "$entry" | jq -r '.sha256')
    local expected_path; expected_path=$(echo "$entry" | jq -r '.expected')
    local notes; notes=$(echo "$entry" | jq -r '.notes // ""')
    local license; license=$(echo "$entry" | jq -r '.upstream_license // "unknown"')

    local tag="${name}-${version}-${arch}"
    local download_basename; download_basename="${url##*/}"
    local download_path="$DOWNLOADS/$download_basename"

    echo ""
    echo "==> [$tag]"
    echo "    URL : $url"

    # Download (idempotent)
    if [[ ! -f "$download_path" ]]; then
        echo "    DL  : downloading ..."
        curl -fsSL --output "$download_path" "$url" || {
            echo "    FAIL: download error"
            SUMMARY+=("FAIL  $tag (download)")
            OVERALL_FAIL=1
            return
        }
    else
        echo "    DL  : cached"
    fi

    # SHA-256 check
    local sha_actual
    sha_actual="$(sha256sum "$download_path" | awk '{print $1}')"
    if [[ "$sha_expected" == "PLACEHOLDER_FILL_ON_FIRST_RUN" ]]; then
        echo "    SHA : placeholder — observed $sha_actual"
        echo "          (update manifest.toml with this value to lock the digest)"
    elif [[ "$sha_expected" != "$sha_actual" ]]; then
        echo "    FAIL: sha256 mismatch"
        echo "          expected: $sha_expected"
        echo "          actual  : $sha_actual"
        SUMMARY+=("FAIL  $tag (sha256)")
        OVERALL_FAIL=1
        return
    else
        echo "    SHA : ok ($sha_actual)"
    fi

    # Extract container if needed → resolve to actual ELF path
    local elf_path="$download_path"
    case "$download_path" in
        *.tar.xz|*.tar.gz|*.tar.bz2|*.tar)
            local extract_dir="${download_path}.extracted"
            mkdir -p "$extract_dir"
            tar -xf "$download_path" -C "$extract_dir"
            elf_path="$(find "$extract_dir" -type f -name "${name##*-}" | head -n1)"
            if [[ -z "$elf_path" ]]; then
                elf_path="$(find "$extract_dir" -type f -executable | head -n1)"
            fi
            ;;
        *.deb)
            local extract_dir="${download_path}.extracted"
            mkdir -p "$extract_dir"
            ( cd "$extract_dir" && ar x "$download_path" && \
              tar -xf data.tar.* )
            # name="coreutils-ls" → look for /usr/bin/ls; name="wget" → /usr/bin/wget
            local short_name="${name##*-}"
            elf_path="$(find "$extract_dir/usr" -type f -name "$short_name" 2>/dev/null | head -n1)"
            if [[ -z "$elf_path" ]]; then
                elf_path="$(find "$extract_dir" -type f -executable | head -n1)"
            fi
            ;;
    esac

    if [[ ! -f "$elf_path" ]]; then
        echo "    FAIL: could not resolve ELF inside container"
        SUMMARY+=("FAIL  $tag (no-elf)")
        OVERALL_FAIL=1
        return
    fi
    echo "    ELF : $elf_path"

    # Run bincheck
    local out_json
    if ! out_json="$("$BINCHECK" "$elf_path" --format json 2>/dev/null)"; then
        echo "    FAIL: bincheck exited with error"
        SUMMARY+=("FAIL  $tag (bincheck)")
        OVERALL_FAIL=1
        return
    fi

    # Compare against expected (key fields only)
    local expected_full="$REPO_ROOT/$expected_path"
    if [[ -f "$expected_full" ]]; then
        local exp_libc exp_linkage exp_fortify
        exp_libc=$(jq -r '.expected.libc // "unknown"' "$expected_full")
        exp_linkage=$(jq -r '.expected.linkage // "unknown"' "$expected_full")
        exp_fortify=$(jq -r '.expected.fortify_source // false' "$expected_full")

        local got_libc got_linkage got_fortify
        got_libc=$(echo "$out_json" | jq -r '.results[0].result.Elf.libc_flavor // "unknown"')
        got_linkage=$(echo "$out_json" | jq -r '.results[0].result.Elf.linkage // "unknown"')
        got_fortify=$(echo "$out_json" | jq -r '.results[0].result.Elf.fortify_source // false')

        local entry_fail=0
        for field in libc linkage fortify; do
            local exp_var="exp_${field}" got_var="got_${field}"
            if [[ "${!exp_var}" != "${!got_var}" ]]; then
                echo "    DIFF: $field expected=${!exp_var} got=${!got_var}"
                entry_fail=1
            fi
        done

        if [[ $entry_fail -eq 0 ]]; then
            SUMMARY+=("PASS  $tag")
        else
            SUMMARY+=("DIFF  $tag")
            OVERALL_FAIL=1
        fi
    else
        echo "    WARN: expected file not found ($expected_path), skipping diff"
        SUMMARY+=("SKIP  $tag (no expected)")
    fi

    # Capture detected info for the doc generator
    local banned_names
    banned_names=$(echo "$out_json" | jq -c '[.results[0].result.Elf.banned_functions[]?.function.name] // []')
    local libc
    libc=$(echo "$out_json" | jq -r '.results[0].result.Elf.libc_flavor // "unknown"')
    local doc_entry
    doc_entry=$(jq -n \
        --arg name "$name" \
        --arg version "$version" \
        --arg arch "$arch" \
        --arg license "$license" \
        --arg url "$url" \
        --arg sha "$sha_actual" \
        --arg libc "$libc" \
        --arg notes "$notes" \
        --argjson banned "$banned_names" \
        '{name:$name, version:$version, arch:$arch, license:$license, url:$url, sha256:$sha, libc:$libc, banned_functions:$banned, notes:$notes}')
    DOC_ENTRIES_JSON=$(jq -c ". + [$doc_entry]" <<<"$DOC_ENTRIES_JSON")
}

for ((i=0; i<ENTRY_COUNT; i++)); do
    verify_one "$i" || true
done

# ---------------------------------------------------------------------------
# Regenerate docs/verified-binaries.md (Ada conditions 1/5/6 reflected)
# ---------------------------------------------------------------------------

echo ""
echo "==> Regenerating $DOC_OUT"
HOST_DESC="$(uname -srm)"
DATE_JST="$(TZ=Asia/Tokyo date +%Y-%m-%d)"

{
    echo "# bincheck verified binaries"
    echo ""
    echo "- **bincheck version**: \`$BINCHECK_VERSION\`"
    echo "- **Verification date (JST)**: $DATE_JST"
    echo "- **Verification host**: $HOST_DESC"
    echo ""
    echo "This document is **regenerated** by \`scripts/verify-external.sh\` from"
    echo "\`tests/external/manifest.toml\` and the live bincheck output. Do not"
    echo "edit by hand — re-run the script and commit the result."
    echo ""
    echo "## Entries"
    echo ""
    echo "$DOC_ENTRIES_JSON" | jq -r '.[] |
        "### \(.name) \(.version) (\(.arch))\n" +
        "- **License (upstream)**: \(.license)\n" +
        "- **URL**: \(.url)\n" +
        "- **SHA-256**: `\(.sha256)`\n" +
        "- **Detected libc flavor**: \(.libc)\n" +
        "- **Banned functions detected**: \(if (.banned_functions|length) == 0 then "none" else (.banned_functions | join(", ")) end)\n" +
        (if .notes != "" then "- **Notes**: \(.notes)\n" else "" end)'
    echo ""
    echo "---"
    echo ""
    echo "All product names mentioned in this document are trademarks or registered"
    echo "trademarks of their respective owners. They are used here solely for"
    echo "descriptive identification of test targets and do not imply endorsement,"
    echo "sponsorship, or affiliation."
} > "$DOC_OUT"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "==> Summary"
for line in "${SUMMARY[@]}"; do
    echo "    $line"
done

if [[ $OVERALL_FAIL -ne 0 ]]; then
    echo ""
    echo "RESULT: at least one entry failed. See diffs above."
    exit 1
fi
echo ""
echo "RESULT: all entries verified. Doc updated at $DOC_OUT"
exit 0
