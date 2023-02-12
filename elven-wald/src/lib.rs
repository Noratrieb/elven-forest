#[macro_use]
extern crate tracing;

use anyhow::{bail, Context, Result};
use clap::Parser;
use elven_parser::{
    consts::{self as c, ShType, SHT_PROGBITS},
    read::{ElfIdent, ElfReader, Offset},
    write::{self, ElfWriter, Entry, Section},
};
use memmap2::Mmap;
use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
};

#[derive(Debug, Clone, Parser)]
pub struct Opts {
    pub objs: Vec<PathBuf>,
}

pub fn run(opts: Opts) -> Result<()> {
    let mmaps = opts
        .objs
        .iter()
        .map(|path| {
            let file =
                fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
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
            ElfReader::new(mmap).with_context(|| format!("parsing ELF file {}", path.display()))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let elf = elfs[0];

    let text_sh = elf.section_header_by_name(b".text")?;
    let text_content = elf.section_content(text_sh)?;

    let _start_sym = elf.symbol_by_name(b"_start")?;

    let section = _start_sym.shndx;

    let entry = Entry {
        section,
        rel_offset: Offset(_start_sym.value.0),
    };

    write_output(text_content, entry)?;

    Ok(())
}

fn write_output(text: &[u8], entry: Entry) -> Result<()> {
    let ident = ElfIdent {
        magic: *c::ELFMAG,
        class: c::Class(c::ELFCLASS64),
        data: c::Data(c::ELFDATA2LSB),
        version: 1,
        osabi: c::OsAbi(c::ELFOSABI_SYSV),
        abiversion: 0,
        _pad: [0; 7],
    };

    let header = write::Header {
        ident,
        r#type: c::Type(c::ET_DYN),
        machine: c::Machine(c::EM_X86_64),
    };

    let mut write = ElfWriter::new(header);

    let text_name = write.add_sh_string(b".text");
    write.add_section(Section {
        name: text_name,
        r#type: ShType(SHT_PROGBITS),
        flags: 0,
        fixed_entsize: None,
        content: text.to_vec(),
    });

    write.set_entry(entry);

    let output = write.write().context("writing output file")?;

    let mut output_file = fs::File::create("a.out").context("creating ./a.out")?;
    BufWriter::new(&mut output_file).write_all(&output)?;

    #[allow(unused_mut)]
    let mut permissions = output_file.metadata()?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o111);
    };
    output_file.set_permissions(permissions)?;

    Ok(())
}
