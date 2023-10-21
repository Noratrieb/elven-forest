mod storage;
mod utils;

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
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    fs::{self, File},
    io::{BufWriter, Write},
    iter,
    num::NonZeroU64,
    path::{Path, PathBuf},
};
use storage::StorageAllocation;

thread_local! {
    static ELF_PATHS: RefCell<Vec<PathBuf>> = RefCell::new(Vec::new());
}

#[derive(Debug, Clone, Parser)]
pub struct Opts {
    #[clap(long, short, default_value = "a.out")]
    pub output: PathBuf,
    pub objs: Vec<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId(usize);

impl Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ELF_PATHS.with(|p| {
            let paths = p.borrow();
            let name = &paths[self.0];
            write!(f, "{}#{{{}}}", self.0, name.display(),)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectionId {
    file: FileId,
    section: SectionIdx,
}

struct ElfFile<'a> {
    id: FileId,
    elf: ElfReader<'a>,
}

#[derive(Debug)]
struct Symbol<'a> {
    name: &'a BStr,
    definition: Option<SymbolDefinition>,
}

#[derive(Debug)]
struct SymbolDefinition {
    location: SectionId,
    value: Addr,
    size: u64,
}

struct LinkCtxt<'a> {
    elves: Vec<ElfFile<'a>>,
    sym_defs: HashMap<&'a BStr, Symbol<'a>>,
    storage: StorageAllocation,
}

pub fn run(opts: Opts) -> Result<()> {
    ELF_PATHS.set(opts.objs.clone());

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

    info!(objs=?opts.objs, "Linking files");

    let elves = mmaps
        .iter()
        .zip(&opts.objs)
        .enumerate()
        .map(|(idx, (mmap, path))| {
            Ok(ElfFile {
                id: FileId(idx),
                elf: ElfReader::new(mmap)
                    .with_context(|| format!("parsing ELF file {}", path.display()))?,
            })
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;

    let storage =
        storage::allocate_storage(BASE_EXEC_ADDR, &elves).context("while allocating storage")?;

    let mut cx = LinkCtxt {
        elves,
        sym_defs: HashMap::new(),
        storage,
    };

    dbg!(&cx.storage);

    cx.sym_first_pass()?;

    let mut writer = create_elf();

    for section in &cx.storage.sections {
        let exec = if section.name == b"text".as_slice() {
            ShFlags::SHF_EXECINSTR
        } else {
            ShFlags::empty()
        };
        let mut content = Vec::new();

        for part in &section.parts {
            let elf = cx.elves[part.file.0].elf;
            let shdr = elf.section_header_by_name(&section.name)?;
            let data = elf.section_content(shdr)?;
            content.extend(iter::repeat(0).take(part.pad_from_prev.try_into().unwrap()));
            content.extend(data);
        }

        let name = writer.add_sh_string(&section.name);
        writer.add_section(Section {
            name,
            r#type: ShType(SHT_PROGBITS),
            flags: ShFlags::SHF_ALLOC | exec,
            fixed_entsize: None,
            addr_align: NonZeroU64::new(
                section
                    .parts
                    .first()
                    .map(|p| p.align)
                    .unwrap_or(DEFAULT_PAGE_ALIGN),
            ),
            content,
        })?;
    }

    write_elf_to_file(writer, &opts.output)?;

    dbg!(cx.sym_defs);

    let text_sh = cx.elves[0].elf.section_header_by_name(b".text")?;
    let text_content = cx.elves[0].elf.section_content(text_sh)?;

    let _start_sym = cx.elves[0].elf.symbol_by_name(b"_start")?;

    write_output(&opts, text_content, _start_sym.value)?;

    Ok(())
}

pub const BASE_EXEC_ADDR: Addr = Addr(0x400000); // whatever ld does
pub const DEFAULT_PAGE_ALIGN: u64 = 0x1000;

impl<'a> LinkCtxt<'a> {
    fn sym_first_pass(&mut self) -> Result<()> {
        for (elf_idx, elf) in self.elves.iter().enumerate() {
            for e_sym in elf.elf.symbols()? {
                let ty = e_sym.info.r#type();

                if ty.0 == c::STT_SECTION {
                    continue;
                }

                let name = elf.elf.string(e_sym.name)?;

                let definition = if e_sym.shndx == SHN_UNDEF {
                    None
                } else {
                    Some(SymbolDefinition {
                        location: SectionId {
                            file: FileId(elf_idx),
                            section: e_sym.shndx,
                        },
                        value: e_sym.value,
                        size: e_sym.size,
                    })
                };

                match self.sym_defs.entry(name) {
                    Entry::Occupied(mut entry) => {
                        match (&mut entry.get_mut().definition, definition) {
                            (Some(_), Some(_)) => bail!("duplicate definition for symbol {name}"),
                            (new @ None, def @ Some(_)) => *new = def,
                            (Some(_), None) => {}
                            (None, None) => {}
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Symbol { name, definition });
                    }
                }
            }
        }

        Ok(())
    }
}

fn create_elf() -> ElfWriter {
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

    ElfWriter::new(header)
}

fn write_output(opts: &Opts, text: &[u8], entry_offset_from_text: Addr) -> Result<()> {
    let mut write = create_elf();

    let text_name = write.add_sh_string(b".text");
    let text_section = write.add_section(Section {
        name: text_name,
        r#type: ShType(SHT_PROGBITS),
        flags: ShFlags::SHF_ALLOC | ShFlags::SHF_EXECINSTR,
        fixed_entsize: None,
        content: text.to_vec(),
        // align nicely
        addr_align: Some(NonZeroU64::new(DEFAULT_PAGE_ALIGN).unwrap()),
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
        align: DEFAULT_PAGE_ALIGN,
    };

    write.add_program_header(elf_header_and_program_headers);

    let entry_addr = BASE_EXEC_ADDR + DEFAULT_PAGE_ALIGN + entry_offset_from_text;

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
        align: DEFAULT_PAGE_ALIGN,
    };

    write.add_program_header(text_program_header);

    write.set_entry(entry_addr);

    write_elf_to_file(write, &opts.output)?;

    Ok(())
}

fn write_elf_to_file(elf: ElfWriter, path: &Path) -> Result<()> {
    let output = elf.write().context("writing output file")?;

    let mut output_file = fs::File::create(path).context("creating ./a.out")?;
    BufWriter::new(&mut output_file).write_all(&output)?;

    make_file_executable(&output_file)
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
