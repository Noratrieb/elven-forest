#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

for rust_file in $SCRIPT_DIR/*.rs; do
    # Use -Cprefer-dynamic to keep the binary small
    rustc --edition 2021 "$rust_file" -Cprefer-dynamic -Copt-level=3 --out-dir="$SCRIPT_DIR/out"
done

for c_obj_file in $SCRIPT_DIR/*_obj.c; do
    cc "$c_obj_file" -c -o "$SCRIPT_DIR/out/$(basename $c_obj_file .c).o"
done

for asm_file in $SCRIPT_DIR/*.asm; do
    nasm "$asm_file" -felf64 -o "$SCRIPT_DIR/out/$(basename $asm_file .asm).o"
done
