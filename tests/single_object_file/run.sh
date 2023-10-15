set -e

nasm -felf64 -o empty empty.asm

"$ELVEN_WALD" empty

./a.out
