use std::{fmt::Display, fs::File};

use anyhow::Context;
use elven_parser::{
    consts::{DynamicTag, ShType, RX86_64},
    defs::{Addr, Elf},
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
    size: u64,
    #[tabled(rename = "type")]
    r#type: ShType,
}

#[derive(Tabled)]
struct RelaTable {
    section: String,
    symbol: String,
    offset: u64,
    #[tabled(rename = "type")]
    r#type: RX86_64,
    addend: u64,
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
                size: sh.size,
                r#type: sh.r#type,
            })
        })
        .collect::<Result<Vec<_>, ElfParseError>>()?;

    print_table(Table::new(sections));

    println!("\nRelocations");

    let relas = elf
        .relas()?
        .map(|(sh, rela)| {
            let section = elf.sh_string(sh.name)?.to_string();

            let sym = elf.symbol(rela.info.sym())?;
            let symbol = elf.string(sym.name)?.to_string();

            let offset = rela.offset.0;
            let r#type = elven_parser::consts::RX86_64(rela.info.r#type());
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

fn print_table(mut table: Table) {
    table.with(Style::blank());
    println!("{table}");
}
