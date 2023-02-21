use std::{
    fmt::Display,
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Parser;
use elven_parser::{
    consts::{self as c, DynamicTag, PhFlags, PhType, ShFlags, ShType, SymbolVisibility, RX86_64},
    read::{ElfReadError, ElfReader, Sym, SymInfo},
    Addr, Offset,
};
use memmap2::Mmap;
use tabled::{object::Rows, Disable, Style, Table, Tabled};

#[derive(Parser)]
struct Opts {
    #[arg(long("file-header"), long("header"))]
    header: bool,
    #[arg(short('l'), long("program-headers"), long("segments"))]
    program_headers: bool,
    #[arg(short('S'), long("section-headers"), long("sections"))]
    section_headers: bool,
    #[arg(short('s'), long("symbols"), long("syms"))]
    symbols: bool,
    #[arg(short('r'), long("relocs"))]
    relocs: bool,
    /// Not in readelf.
    #[arg(short('d'), long("dyns"))]
    dyns: bool,
    files: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    for obj in &opts.files {
        print_file(&opts, obj).with_context(|| format!("Failed to print {}", obj.display()))?;
    }

    Ok(())
}

#[derive(Tabled)]
struct HeaderTable<'a>(&'static str, &'a dyn Display);

// Not really an addr but just display it as hex.
type Hex = Addr;

#[derive(Tabled)]
struct SectionTable {
    name: String,
    #[tabled(rename = "type")]
    r#type: ShType,
    size: Hex,
    offset: Offset,
    flags: ShFlags,
}

#[derive(Tabled)]
struct ProgramHeaderTable {
    #[tabled(rename = "type")]
    r#type: PhType,
    flags: PhFlags,
    offset: Offset,
    virtual_addr: Addr,
    phys_addr: Addr,
    file_size: Hex,
    mem_size: Hex,
    align: Hex,
    inside_section: String,
    inside_section_offset: Offset,
}

#[derive(Tabled)]
struct SymbolTable {
    name: String,
    info: SymInfo,
    other: SymbolVisibility,
    section: String,
    value: Addr,
    size: u64,
}

#[derive(Tabled)]
struct RelaTable {
    section: String,
    symbol: String,
    offset: Addr,
    #[tabled(rename = "type")]
    r#type: RX86_64,
    addend: i64,
}

#[derive(Tabled)]
struct DynTable {
    tag: DynamicTag,
    value: Addr,
}

fn print_file(opts: &Opts, path: &Path) -> anyhow::Result<()> {
    println!("{}", path.display());

    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file) }?;

    let elf = ElfReader::new(&mmap)?;

    if opts.header {
        println!("\nHeader");

        let header = elf.header()?;
        let ident = header.ident;
        let header_tab = vec![
            HeaderTable("class", &ident.class),
            HeaderTable("data", &ident.data),
            HeaderTable("version", &ident.version),
            HeaderTable("osabi", &ident.osabi),
            HeaderTable("type", &header.r#type),
            HeaderTable("machine", &header.machine),
            HeaderTable("entrypoint", &header.entry),
            HeaderTable("header size", &header.ehsize),
            HeaderTable("program header size", &header.phentsize),
            HeaderTable("section header size", &header.shentsize),
        ];

        let mut table = Table::new(header_tab);
        // No header
        table.with(Disable::row(Rows::first()));
        print_table(table);
    }

    if opts.section_headers {
        println!("\nSections");

        let sections = elf
            .section_headers()?
            .iter()
            .map(|sh| {
                let name = elf.sh_string(sh.name)?.to_string();
                Ok(SectionTable {
                    name,
                    r#type: sh.r#type,
                    size: Addr(sh.size),
                    offset: sh.offset,
                    flags: sh.flags,
                })
            })
            .collect::<Result<Vec<_>, ElfReadError>>()?;

        print_table(Table::new(sections));
    }

    if opts.program_headers {
        println!("\nProgram headers");

        let sections = elf
            .program_headers()?
            .iter()
            .map(|ph| {
                let (inside_section, inside_section_offset) =
                    section_name_of_offset(elf, ph.offset)?;

                Ok(ProgramHeaderTable {
                    r#type: ph.r#type,
                    flags: ph.flags,
                    offset: ph.offset,
                    virtual_addr: ph.vaddr,
                    phys_addr: ph.paddr,
                    file_size: Addr(ph.filesz),
                    mem_size: Addr(ph.memsz),
                    align: Addr(ph.align),
                    inside_section,
                    inside_section_offset,
                })
            })
            .collect::<Result<Vec<_>, ElfReadError>>()?;

        print_table(Table::new(sections));
    }

    if opts.symbols {
        println!("\nSymbols");

        let symbols = elf
            .symbols()?
            .iter()
            .map(|sym| {
                let name = sym_display_name(elf, sym)?;
                let section = match sym.shndx.0 {
                    c::SHN_ABS | c::SHN_COMMON => String::new(),
                    _ => elf
                        .sh_string(elf.section_header(sym.shndx)?.name)?
                        .to_string(),
                };

                Ok(SymbolTable {
                    name,
                    info: sym.info,
                    other: sym.other,
                    section,
                    size: sym.size,
                    value: sym.value,
                })
            })
            .collect::<Result<Vec<_>, ElfReadError>>()?;

        print_table(Table::new(symbols));
    }

    if opts.relocs {
        println!("\nRelocations");

        let relas = elf
            .relas()?
            .map(|(sh, rela)| {
                let section = elf.sh_string(sh.name)?.to_string();

                let sym = elf.symbol(rela.info.sym())?;

                let symbol = sym_display_name(elf, sym)?;

                let offset = rela.offset;
                let r#type = c::RX86_64(rela.info.r#type());
                let addend = rela.addend;

                Ok(RelaTable {
                    section,
                    symbol,
                    offset,
                    r#type,
                    addend,
                })
            })
            .collect::<Result<Vec<_>, ElfReadError>>()?;

        print_table(Table::new(relas));
    }

    if opts.dyns {
        if let Ok(dyns) = elf.dyn_entries() {
            println!("\nDynamic entries");

            let dyns = dyns.iter().map(|dy| DynTable {
                tag: dy.tag,
                value: Addr(dy.val),
            });
            print_table(Table::new(dyns));
        }
    }

    println!();

    Ok(())
}

fn section_name_of_offset(
    elf: ElfReader<'_>,
    offset: Offset,
) -> Result<(String, Offset), ElfReadError> {
    for sh in elf.section_headers()?.iter() {
        let range = sh.offset..(sh.offset + sh.size);
        if range.contains(&offset) {
            let name = sh.name;
            let name = elf.sh_string(name)?;

            let offset = offset - sh.offset;

            return Ok((name.to_string(), offset));
        }
    }

    Ok((String::new(), offset))
}

fn sym_display_name(elf: ElfReader<'_>, sym: &Sym) -> Result<String, ElfReadError> {
    Ok(if sym.info.r#type() == c::STT_SECTION {
        elf.sh_string(elf.section_header(sym.shndx)?.name)?
            .to_string()
    } else {
        elf.string(sym.name)?.to_string()
    })
}

fn print_table(mut table: Table) {
    table.with(Style::blank());
    println!("{table}");
}
