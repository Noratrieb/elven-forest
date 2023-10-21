use anyhow::Result;
use bstr::{BStr, BString};
use elven_parser::{read::ElfReadError, Addr};
use indexmap::IndexMap;

use crate::{utils::AlignExt, ElfFile, FileId, DEFAULT_PAGE_ALIGN};

#[derive(Debug)]
pub struct Allocation {
    pub file: FileId,
    pub section: BString,
    pub size: u64,
    pub align: u64,
}

#[derive(Debug)]
pub struct SegmentPart {
    pub pad_from_prev: u64,
    pub base: Addr,
    pub align: u64,
    pub file: FileId,
    pub size: u64,
}

#[derive(Debug)]
pub struct StorageAllocation {
    pub sections: Vec<AllocatedSection>,
}

#[derive(Debug)]
pub struct AllocatedSection {
    pub name: BString,
    pub parts: Vec<SegmentPart>,
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
    let mut section_parts = Vec::new();
    for section in allocs {
        let mut segment_parts = Vec::new();

        current_addr = current_addr.align_up(DEFAULT_PAGE_ALIGN);
        for alloc in section.1 {
            let align = alloc.align;
            let addr = current_addr.align_up(align);
            let pad = addr.u64() - current_addr.u64();

            current_addr = addr + alloc.size;

            segment_parts.push(SegmentPart {
                pad_from_prev: pad,
                base: addr,
                align: align,
                file: alloc.file,
                size: alloc.size,
            });
        }

        section_parts.push(AllocatedSection {
            name: section.0.to_owned(),
            parts: segment_parts,
        })
    }

    Ok(StorageAllocation {
        sections: section_parts,
    })
}
