use anyhow::{Context, Result};
use elven_parser::read::ElfReader;

pub fn analyze_text_bloat(elf: ElfReader<'_>) -> Result<()> {
    let text = elf
        .section_header_by_name(b".text")
        .context(".text not found")?;

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
        let components =
            symbol_components(std::str::from_utf8(sym)?).with_context(|| sym.to_string())?;

        println!("{size} {components}");
    }

    Ok(())
}

fn symbol_components(sym: &str) -> Result<String> {
    let demangled = rustc_demangle::demangle(sym).to_string();

    if demangled.starts_with('<') {
        let qpath = parse_qpath(&demangled).context("invalid qpath")?;
        let components = qpath_components(qpath)?;

        // qpath
        return Ok(components.join(","));
    } else {
        // normal path
        let components = demangled.split("::").collect::<Vec<_>>();
        let path = components.join(",");
        return Ok(path);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct QPath<'a> {
    qself: &'a str,
    trait_: &'a str,
    pathy_bit: &'a str,
}

fn qpath_components(qpath: QPath<'_>) -> Result<Vec<&str>> {
    if qpath.qself.starts_with('<') {
        let sub_qpath = parse_qpath(qpath.qself)?;
        let mut sub_components = qpath_components(sub_qpath)?;
        sub_components.extend(qpath.pathy_bit.split("::"));
        Ok(sub_components)
    } else {
        Ok(qpath
            .qself
            .split("::")
            .chain(qpath.pathy_bit.split("::"))
            .collect())
    }
}

// FIXME: Apparently the symbol `std::os::linux::process::<impl core::convert::From<std::os::linux::process::PidFd> for std::os::fd::owned::OwnedFd>::from` exists in std
// I have no clue what to do about that.

fn parse_qpath(s: &str) -> Result<QPath<'_>> {
    let mut chars = s.char_indices().skip(1);
    let mut angle_brackets = 1u64;

    let mut result = None;
    let mut as_idx = None;

    while let Some((idx, char)) = chars.next() {
        match char {
            '<' => angle_brackets += 1,
            '>' => {
                angle_brackets -= 1;
                if angle_brackets == 0 {
                    result = Some(idx);
                    break;
                }
            }
            ' ' => {
                if angle_brackets == 1 && as_idx == None {
                    as_idx = Some(idx);
                }
            }
            _ => {}
        }
    }

    let q_close_idx = result.with_context(|| {
        format!("qualified symbol `{s}` does not end qualified part with > properly")
    })?;

    let as_idx =
        as_idx.with_context(|| format!("qualified symbol `{s}` does not contain ` as `"))?;

    let q = &s[..q_close_idx];
    let pathy_bit = &s[q_close_idx + 1..];
    let pathy_bit = pathy_bit.strip_prefix("::").with_context(|| {
        format!("path after qualification does not start with `::`: `{pathy_bit}`")
    })?;

    let qself = &q[1..as_idx];
    let trait_ = &q[(as_idx + " as ".len())..];

    Ok(QPath {
        qself,
        trait_,
        pathy_bit,
    })
}

#[cfg(test)]
mod tests {
    use crate::size::QPath;

    use super::{parse_qpath, symbol_components};

    #[test]
    fn parse_qpaths() {
        assert_eq!(
            parse_qpath("<std::path::Components as core::fmt::Debug>::fmt").unwrap(),
            QPath {
                qself: "std::path::Components",
                trait_: "core::fmt::Debug",
                pathy_bit: "fmt",
            }
        );

        assert_eq!(
            parse_qpath("<<std::path::Components as core::fmt::Debug>::fmt::DebugHelper as core::fmt::Debug>::fmt").unwrap(),
            QPath {
                qself: "<std::path::Components as core::fmt::Debug>::fmt::DebugHelper",
                trait_: "core::fmt::Debug",
                pathy_bit: "fmt",
            }
        );
    }

    #[test]
    fn path_debug_helper() {
        // <<std::path::Components as core::fmt::Debug>::fmt::DebugHelper as core::fmt::Debug>::fmt::h4f87ac80fb33df05
        let sym = "_ZN106_$LT$$LT$std..path..Iter$u20$as$u20$core..fmt..Debug$GT$..fmt..DebugHelper$u20$as$u20$core..fmt..Debug$GT$3fmt17h4f87ac80fb33df05E";
        let components = symbol_components(sym).unwrap();

        assert_eq!(
            components,
            "std,path,Iter,fmt,DebugHelper,fmt,h4f87ac80fb33df05"
        )
    }
}
