use std::ops::Add;

use anyhow::Result;
use bstr::{BStr, BString};
use elven_parser::{read::ElfReadError, Addr};
use indexmap::IndexMap;

use crate::{utils::AlignExt, ElfFile, FileId, DEFAULT_PAGE_ALIGN};

#[derive(Debug)]
pub struct Allocation {
    file: FileId,
    section: BString,
    size: u64,
    align: u64,
}

#[derive(Debug)]
pub struct SegmentPart {
    base: Addr,
    file: FileId,
    section: BString,
    size: u64,
}

#[derive(Debug)]
pub struct StorageAllocation {
    segment_parts: Vec<SegmentPart>,
}

pub fn allocate_storage<'a>(base_addr: Addr, files: &[ElfFile<'a>]) -> Result<StorageAllocation> {
    let mut allocs = IndexMap::<_, Vec<Allocation>>::new();

    for file in files {
        let elf = file.elf;

        for name in [b".text".as_slice(), b".data", b".bss"] {
            let section = elf.section_header_by_name(name);
            match section {
                Ok(section) => {
                    allocs.entry(BStr::new(name)).or_default().push(Allocation {
                        file: file.id,
                        section: name.into(),
                        size: section.size,
                        align: section.addralign,
                    });
                }
                Err(ElfReadError::NotFoundByName(_, _)) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    debug!(?allocs, "Allocation pass one completed");

    let mut current_addr = base_addr;
    let mut segment_parts = Vec::new();
    for section in allocs {
        current_addr = current_addr.align_up(DEFAULT_PAGE_ALIGN);
        for alloc in section.1 {
            let align = alloc.align;
            let addr = current_addr.align_up(align);

            current_addr = addr + alloc.size;

            segment_parts.push(SegmentPart {
                base: addr,
                file: alloc.file,
                size: alloc.size,
                section: section.0.to_owned(),
            });
        }
    }

    Ok(StorageAllocation { segment_parts })
}
