use anyhow::{Context, Result};
use elven_parser::read::ElfReader;

pub fn analyze_text_bloat(elf: ElfReader<'_>) -> Result<()> {
    let text = elf
        .section_header_by_name(b".text")
        .context(".text not found")?;
    dbg!(text.size);

    let syms = elf.symbols().context("symbols not found")?;

    let text_range = text.addr..(text.addr + text.size);

    let mut symbols_sorted = syms
        .into_iter()
        .filter(|sym| text_range.contains(&sym.value))
        .collect::<Vec<_>>();

    symbols_sorted.sort_by_key(|s| s.value);

    let mut symbol_sizes = Vec::new();

    for syms in symbols_sorted.windows(2) {
        let [first, second] = syms else {
            unreachable!()
        };
        let first_size = second.value.u64() - first.value.u64();

        let sym_name = elf.string(first.name)?;

        symbol_sizes.push((sym_name, first_size));
    }

    symbol_sizes.sort_by_key(|&(_, size)| size);
    symbol_sizes.reverse();

    for (sym, size) in symbol_sizes {
        println!("{size} {sym}");
    }

    Ok(())
}
