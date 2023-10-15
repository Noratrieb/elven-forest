#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

cargo build -p elven-wald --manifest-path "$SCRIPT_DIR/Cargo.toml"

export ELVEN_WALD="$SCRIPT_DIR/target/debug/elven-wald"

for dir in "$SCRIPT_DIR"/tests/*; do
    echo "Testing $(basename "$dir")"
    tmpdir=$(mktemp -d)
    cp -r "$dir" "$tmpdir"
    cd "$tmpdir/$(basename "$dir")" || exit 1
    if ! bash "$dir/run.sh" >"$tmpdir/__stderr" 2>&1; then
    cat "$tmpdir/__stderr"
        echo "failed"
    else
        echo "passed"
    fi
done
