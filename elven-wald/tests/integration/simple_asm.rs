use std::process::Command;

use crate::prelude::*;

use super::run;

#[test]
fn single_object_file() {
    let ctx = ctx();

    let empty = ctx.nasm(
        "empty",
        "
    global _start
        section .text
    _start:
        mov rax, 60
        mov rdi, 0
        syscall
    ",
    );

    let out = elven_wald!(ctx; empty);
    run(Command::new(out));
}

#[test]
fn two_object_files() {
    let ctx = ctx();

    let start = ctx.nasm(
        "start",
        "
        global _start
        extern exit 

        section .text
        _start:
            call exit
    ",
    );
    let exit = ctx.nasm(
        "exit",
        "
        global exit
        section .text
        exit:
            mov rax, 60
            mov rdi, 0
            syscall
    ",
    );

    let out = elven_wald!(ctx; start, exit);
    run(Command::new(out));
}
