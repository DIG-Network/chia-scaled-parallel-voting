#!/usr/bin/env bash
# build.sh
# Compile every Rue puzzle entry-point in this project to CLVM bytecode.
#
# For each entry-point .rue file in puzzles/, emits two files in
# puzzles/compiled/<relative-path>/:
#   <name>.rue.hex   — CLVM bytecode in hex
#   <name>.rue.hash  — puzzle tree hash in hex
#
# Library-only files (those without a `main` function) are skipped.

set -euo pipefail

# Library files (no `main` function — only types/helpers, imported by entry points).
LIBRARIES=(
    "puzzles/common_types.rue"
    "puzzles/finalizer.rue"
    "puzzles/merkle_utils.rue"
    "puzzles/poseidon.rue"
    "puzzles/election/shared.rue"
    "puzzles/registration_coin/shared.rue"
    "puzzles/ballot_coin/shared.rue"
    "puzzles/voting_coin/shared.rue"
)

is_library() {
    local f="$1"
    for lib in "${LIBRARIES[@]}"; do
        if [[ "$f" == "$lib" ]]; then return 0; fi
    done
    return 1
}

OUT_ROOT="puzzles/compiled"
rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT"

built=0
failed=()

while IFS= read -r rue_file; do
    if is_library "$rue_file"; then continue; fi

    rel_path="${rue_file#puzzles/}"
    out_dir="$OUT_ROOT/$(dirname "$rel_path")"
    base_name="$(basename "$rel_path")"
    mkdir -p "$out_dir"
    hex_path="$out_dir/${base_name}.hex"
    hash_path="$out_dir/${base_name}.hash"

    echo "Building $rue_file"

    # rue build prints warnings to stderr; we only want stdout.
    if ! hex="$(rue build "$rue_file" --hex 2>/dev/null)" || [[ -z "$hex" ]]; then
        echo "  FAILED to build hex for $rue_file" >&2
        failed+=("$rue_file")
        continue
    fi
    if ! hash="$(rue build "$rue_file" --hash 2>/dev/null)" || [[ -z "$hash" ]]; then
        echo "  FAILED to build hash for $rue_file" >&2
        failed+=("$rue_file")
        continue
    fi

    printf '%s' "$hex"  > "$hex_path"
    printf '%s' "$hash" > "$hash_path"
    built=$((built + 1))
done < <(find puzzles -name "*.rue" -type f | sort)

if (( ${#failed[@]} > 0 )); then
    echo
    echo "Failed to build:" >&2
    for f in "${failed[@]}"; do echo "  $f" >&2; done
    exit 1
fi

echo
echo "Built $built puzzle(s) into $OUT_ROOT/"
