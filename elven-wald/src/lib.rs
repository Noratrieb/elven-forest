#[macro_use]
extern crate tracing;

use anyhow::{bail, Context, Result};
use bstr::BStr;
use clap::Parser;
use elven_parser::{
    consts::{self as c, PhFlags, SectionIdx, ShFlags, ShType, PT_LOAD, SHN_UNDEF, SHT_PROGBITS},
    read::{ElfIdent, ElfReader},
    write::{self, ElfWriter, ProgramHeader, Section, SectionRelativeAbsoluteAddr},
    Addr, Offset,
};
use memmap2::Mmap;
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::{self, File},
    io::{BufWriter, Write},
    num::NonZeroU64,
    path::PathBuf,
};

#[derive(Debug, Clone, Parser)]
pub struct Opts {
    pub objs: Vec<PathBuf>,
}

#[derive(Debug)]
struct SymDef<'a> {
    _name: &'a BStr,
    defined_in: u32,
    /// `shndx` from ELF
    _refers_to_section: SectionIdx,
}

struct LinkCtxt<'a> {
    elves: Vec<ElfReader<'a>>,
    sym_defs: HashMap<&'a BStr, SymDef<'a>>,
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

    let elves = mmaps
        .iter()
        .zip(&opts.objs)
        .map(|(mmap, path)| {
            ElfReader::new(mmap).with_context(|| format!("parsing ELF file {}", path.display()))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let mut cx = LinkCtxt {
        elves,
        sym_defs: HashMap::new(),
    };

    cx.resolve()?;

    dbg!(cx.sym_defs);

    let text_sh = cx.elves[0].section_header_by_name(b".text")?;
    let text_content = cx.elves[0].section_content(text_sh)?;

    let _start_sym = cx.elves[0].symbol_by_name(b"_start")?;

    write_output(text_content, _start_sym.value)?;

    Ok(())
}

pub const BASE_EXEC_ADDR: Addr = Addr(0x400000); // whatever ld does
pub const DEFAULT_PROGRAM_HEADER_ALIGN_THAT_LD_USES_HERE: u64 = 0x1000;

impl<'a> LinkCtxt<'a> {
    fn resolve(&mut self) -> Result<()> {
        for (elf_idx, elf) in self.elves.iter().enumerate() {
            for e_sym in elf.symbols()? {
                let ty = e_sym.info.r#type();

                // Undefined symbols are not a definition.
                if e_sym.shndx == SHN_UNDEF {
                    continue;
                }

                let name = match ty.0 {
                    c::STT_SECTION => elf.sh_string(elf.section_header(e_sym.shndx)?.name)?,
                    _ => elf.string(e_sym.name)?,
                };

                match self.sym_defs.entry(name) {
                    Entry::Occupied(entry) => {
                        bail!("duplicate symbol {name}. Already defined in {}, duplicate definition in {}", entry.get().defined_in, elf_idx);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(SymDef {
                            _name: name,
                            defined_in: elf_idx as u32,
                            _refers_to_section: e_sym.shndx,
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

fn write_output(text: &[u8], entry_offset_from_text: Addr) -> Result<()> {
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
        r#type: c::Type(c::ET_EXEC),
        machine: c::Machine(c::EM_X86_64),
    };

    let mut write = ElfWriter::new(header);

    let text_name = write.add_sh_string(b".text");
    let text_section = write.add_section(Section {
        name: text_name,
        r#type: ShType(SHT_PROGBITS),
        flags: ShFlags::SHF_ALLOC | ShFlags::SHF_EXECINSTR,
        fixed_entsize: None,
        content: text.to_vec(),
        // align nicely
        addr_align: Some(NonZeroU64::new(DEFAULT_PROGRAM_HEADER_ALIGN_THAT_LD_USES_HERE).unwrap()),
    })?;

    let elf_header_and_program_headers = ProgramHeader {
        r#type: PT_LOAD.into(),
        flags: PhFlags::PF_R,
        offset: SectionRelativeAbsoluteAddr {
            section: SectionIdx(0),
            rel_offset: Offset(0),
        },
        vaddr: BASE_EXEC_ADDR,
        paddr: BASE_EXEC_ADDR,
        filesz: 176, // FIXME: Do not hardocde this lol
        memsz: 176,
        align: DEFAULT_PROGRAM_HEADER_ALIGN_THAT_LD_USES_HERE,
    };

    write.add_program_header(elf_header_and_program_headers);

    let entry_addr =
        BASE_EXEC_ADDR + DEFAULT_PROGRAM_HEADER_ALIGN_THAT_LD_USES_HERE + entry_offset_from_text;

    let text_program_header = ProgramHeader {
        r#type: PT_LOAD.into(),
        flags: PhFlags::PF_X | PhFlags::PF_R,
        offset: SectionRelativeAbsoluteAddr {
            section: text_section,
            rel_offset: Offset(0),
        },
        vaddr: entry_addr,
        paddr: entry_addr,
        filesz: text.len() as u64,
        memsz: text.len() as u64,
        align: DEFAULT_PROGRAM_HEADER_ALIGN_THAT_LD_USES_HERE,
    };

    write.add_program_header(text_program_header);

    write.set_entry(entry_addr);

    let output = write.write().context("writing output file")?;

    let mut output_file = fs::File::create("a.out").context("creating ./a.out")?;
    BufWriter::new(&mut output_file).write_all(&output)?;

    make_file_executable(&output_file)?;

    Ok(())
}

fn make_file_executable(file: &File) -> Result<()> {
    #[allow(unused_mut)]
    let mut permissions = file.metadata()?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o111);
    };
    file.set_permissions(permissions)?;
    Ok(())
}
