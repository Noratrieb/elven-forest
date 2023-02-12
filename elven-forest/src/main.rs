use std::{fmt::Display, fs::File};

use anyhow::Context;
use elven_parser::{
    consts::{self as c, DynamicTag, ShType, SymbolVisibility, RX86_64},
    defs::{Addr, Elf, Sym, SymInfo},
    ElfParseError,
};
use memmap2::Mmap;
use tabled::{object::Rows, Disable, Style, Table, Tabled};

fn main() -> anyhow::Result<()> {
    let objs = std::env::args().skip(1);

    for obj in objs {
        print_file(&obj).with_context(|| format!("Failed to print {obj}"))?;
    }

    Ok(())
}

#[derive(Tabled)]
struct HeaderTable<'a>(&'static str, &'a dyn Display);

#[derive(Tabled)]
struct SectionTable {
    name: String,
    #[tabled(rename = "type")]
    r#type: ShType,
    size: u64,
    offset: u64,
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

fn print_file(path: &str) -> anyhow::Result<()> {
    println!("{path}");

    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file) }?;

    let elf = Elf::new(&mmap)?;

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
    ];

    let mut table = Table::new(header_tab);
    // No header
    table.with(Disable::row(Rows::first()));
    print_table(table);

    println!("\nSections");

    let sections = elf
        .section_headers()?
        .iter()
        .map(|sh| {
            let name = elf.sh_string(sh.name)?.to_string();
            Ok(SectionTable {
                name,
                r#type: sh.r#type,
                size: sh.size,
                offset: sh.offset.0,
            })
        })
        .collect::<Result<Vec<_>, ElfParseError>>()?;

    print_table(Table::new(sections));

    println!("\nSymbols");

    let symbols = elf
        .symbols()?
        .iter()
        .map(|sym| {
            let name = sym_display_name(elf, sym)?;
            let section = match sym.shndx.0 {
                c::SHN_ABS => " ".to_string(),
                c::SHN_COMMON => "".to_string(),
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
        .collect::<Result<Vec<_>, ElfParseError>>()?;

    print_table(Table::new(symbols));

    println!("\nRelocations");

    let relas = elf
        .relas()?
        .map(|(sh, rela)| {
            let section = elf.sh_string(sh.name)?.to_string();

            let sym = elf.symbol(rela.info.sym())?;

            let symbol = sym_display_name(elf, sym)?;

            let offset = Addr(rela.offset.0);
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
        .collect::<Result<Vec<_>, ElfParseError>>()?;

    print_table(Table::new(relas));

    if let Ok(dyns) = elf.dyn_entries() {
        println!("\nDynamic entries");

        let dyns = dyns.iter().map(|dy| DynTable {
            tag: dy.tag,
            value: Addr(dy.val),
        });
        print_table(Table::new(dyns));
    }

    println!();

    Ok(())
}

fn sym_display_name(elf: Elf<'_>, sym: &Sym) -> Result<String, ElfParseError> {
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
