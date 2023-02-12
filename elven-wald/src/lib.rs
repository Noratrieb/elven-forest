#[macro_use]
extern crate tracing;

use anyhow::{bail, Context, Result};
use clap::Parser;
use elven_parser::defs::Elf;
use memmap2::Mmap;
use std::{fs::File, path::PathBuf};

#[derive(Debug, Clone, Parser)]
pub struct Opts {
    pub objs: Vec<PathBuf>,
}

pub fn run(opts: Opts) -> Result<()> {
    let mmaps = opts
        .objs
        .iter()
        .map(|path| {
            let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
            unsafe {
                Mmap::map(&file).with_context(|| format!("memory mapping {}", path.display()))
            }
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    if opts.objs.len() == 0 {
        bail!("you gotta supply at least one object file");
    }

    if opts.objs.len() > 1 {
        bail!("hey hey hey one stop back please. you want to link MULTIPLE files TOGETHER? im sorry i cant do that");
    }

    info!(objs=?opts.objs, "Linking files");

    let elfs = mmaps
        .iter()
        .zip(&opts.objs)
        .map(|(mmap, path)| {
            Elf::new(mmap).with_context(|| format!("parsing ELF file {}", path.display()))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let main_elf = elfs[0];

    Ok(())
}
