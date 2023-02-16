use bytemuck::Pod;

use crate::consts::{Machine, PhFlags, PhType, SectionIdx, ShType, Type, SHT_NULL, SHT_STRTAB};
use crate::read::{self, Addr, ElfHeader, ElfIdent, Offset, Phdr, ShStringIdx, Shdr};
use std::io::Write;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::{io, mem};

#[derive(Debug, thiserror::Error)]
pub enum WriteElfError {
    #[error("Too many {0}")]
    TooMany(&'static str),
    #[error("Writer IO error")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, WriteElfError>;

#[derive(Debug, Clone)]
pub struct ElfWriter {
    header: read::ElfHeader,
    sections: Vec<Section>,
    programs_headers: Vec<ProgramHeader>,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub ident: ElfIdent,
    pub r#type: Type,
    pub machine: Machine,
}

#[derive(Debug, Clone, Copy)]
pub struct SectionRelativeAbsoluteAddr {
    pub section: SectionIdx,
    pub rel_offset: Offset,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: read::ShStringIdx,
    pub r#type: ShType,
    pub flags: u64,
    pub fixed_entsize: Option<NonZeroU64>,
    pub addr_align: Option<NonZeroU64>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub r#type: PhType,
    pub flags: PhFlags,
    pub offset: SectionRelativeAbsoluteAddr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

const SH_STRTAB: usize = 1;

impl ElfWriter {
    pub fn new(header: Header) -> Self {
        let header = read::ElfHeader {
            ident: header.ident,
            r#type: header.r#type,
            machine: header.machine,
            version: 1,
            entry: Addr(0x3333333333333333),
            phoff: Offset(0),
            shoff: Offset(0),
            flags: u32::MAX,
            ehsize: size_of::<read::ElfHeader>() as u16,
            phentsize: size_of::<read::Phdr>() as u16,
            phnum: 0x3333,
            shentsize: size_of::<read::Shdr>() as u16,
            shnum: 0x3333,
            // Set below.
            shstrndex: SectionIdx(SH_STRTAB as u16),
        };

        let null_section = Section {
            // The null string.
            name: read::ShStringIdx(0),
            r#type: ShType(SHT_NULL),
            flags: 0,
            content: Vec::new(),
            fixed_entsize: None,
            addr_align: None,
        };

        let shstrtab = Section {
            // The first string which happens to be .shstrtab below.
            name: read::ShStringIdx(1),
            r#type: ShType(SHT_STRTAB),
            flags: 0,
            // Set up the null string and also the .shstrtab, our section.
            content: b"\0.shstrtab\0".to_vec(),
            fixed_entsize: None,
            addr_align: None,
        };

        Self {
            header,
            sections: vec![null_section, shstrtab],
            programs_headers: Vec::new(),
        }
    }

    pub fn set_entry(&mut self, entry: Addr) {
        self.header.entry = entry;
    }

    pub fn add_sh_string(&mut self, content: &[u8]) -> ShStringIdx {
        let shstrtab = &mut self.sections[SH_STRTAB];
        let idx = shstrtab.content.len();
        shstrtab.content.extend(content);
        shstrtab.content.push(0);
        ShStringIdx(idx as u32)
    }

    pub fn add_section(&mut self, section: Section) -> Result<SectionIdx> {
        let len = self.sections.len();
        self.sections.push(section);
        Ok(SectionIdx(
            len.try_into()
                .map_err(|_| WriteElfError::TooMany("sections"))?,
        ))
    }

    pub fn add_program_header(&mut self, ph: ProgramHeader) {
        self.programs_headers.push(ph);
    }
}

struct Layout {
    // Header
    // Program Headers
    ph_amount: usize,
    // Sections
    sh_amount: usize,
    // Section contents
    section_content_offsets: Vec<Offset>,
    // happy void
    section_content_end_offset: usize,
}

impl Layout {
    fn ph_offset(&self) -> usize {
        mem::size_of::<ElfHeader>()
    }

    fn phs_byte_size(&self) -> usize {
        self.ph_amount * size_of::<read::Phdr>()
    }

    fn sh_offset(&self) -> usize {
        self.ph_offset() + self.phs_byte_size()
    }

    fn shs_byte_size(&self) -> usize {
        self.sh_amount * size_of::<read::Shdr>()
    }

    fn section_contents_offset(&self) -> usize {
        self.sh_offset() + self.shs_byte_size()
    }
}

impl ElfWriter {
    fn layout(&self) -> Layout {
        let mut layout = Layout {
            sh_amount: self.sections.len(),
            ph_amount: self.programs_headers.len(),
            section_content_offsets: Vec::new(),
            section_content_end_offset: 0,
        };

        // Calculate section offsets. Each section pads itself to something nice.
        // They are in order, no fancy layout algorithm.

        let mut current_offset = layout.section_contents_offset() as u64;

        for section in self.sections.iter() {
            if section.content.len() == 0 {
                layout.section_content_offsets.push(Offset(0));
                continue;
            }

            let offset = align_up(
                current_offset,
                section.addr_align.map(NonZeroU64::get).unwrap_or(1),
            );

            current_offset = offset;

            layout.section_content_offsets.push(Offset(offset));

            current_offset += section.content.len() as u64;
        }

        debug_assert_eq!(self.sections.len(), layout.section_content_offsets.len());

        layout.section_content_end_offset = layout.section_content_offsets.last().unwrap().0
            as usize
            + self.sections.last().unwrap().content.len();

        layout
    }

    pub fn write(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        let mut header = self.header;

        header.shnum = self
            .sections
            .len()
            .try_into()
            .map_err(|_| WriteElfError::TooMany("sections"))?;

        header.phnum = self
            .programs_headers
            .len()
            .try_into()
            .map_err(|_| WriteElfError::TooMany("program headers"))?;

        let layout = self.layout();

        // ld orderes it ph/sh apparently so we will do the same

        if !self.programs_headers.is_empty() {
            header.phoff = Offset(layout.ph_offset() as u64);
        }

        if !self.sections.is_empty() {
            header.shoff = Offset(layout.sh_offset() as u64);
        }

        write_pod(&header, &mut output);

        // We know have a few clues about section offsets, so write the program headers.
        for program_header in self.programs_headers.iter() {
            let rel_offset = program_header.offset;
            let section_content_offset =
                layout.section_content_offsets[rel_offset.section.0 as usize];

            let offset = Offset(section_content_offset.0 as u64 + rel_offset.rel_offset.0);

            let ph = Phdr {
                r#type: program_header.r#type,
                flags: program_header.flags,
                offset,
                vaddr: program_header.vaddr,
                paddr: program_header.paddr,
                filesz: program_header.filesz,
                memsz: program_header.memsz,
                align: program_header.align,
            };

            write_pod(&ph, &mut output);
        }

        assert_eq!(output.len(), layout.sh_offset());

        let null_sh = Shdr {
            name: ShStringIdx(0),
            r#type: ShType(SHT_NULL),
            flags: 0,
            addr: Addr(0),
            offset: Offset(0),
            size: 0,
            link: 0,
            info: 0,
            addralign: 0,
            entsize: 0,
        };
        write_pod(&null_sh, &mut output);

        for (i, section) in self.sections.iter().enumerate().skip(1) {
            let offset = layout.section_content_offsets[i];
            let header = Shdr {
                name: section.name,
                r#type: section.r#type,
                flags: section.flags,
                addr: Addr(0),
                offset,
                size: section.content.len() as u64,
                link: 0,
                info: 0,
                addralign: 0,
                entsize: section.fixed_entsize.map(NonZeroU64::get).unwrap_or(0),
            };

            write_pod(&header, &mut output);
        }

        assert_eq!(output.len(), layout.section_contents_offset());

        for (i, section) in self.sections.iter().enumerate() {
            let section_size = section.content.len() as u64;
            if section_size != 0 {
                let current_offest = output.len();
                let supposed_offset = layout.section_content_offsets[i];
                let pre_padding = supposed_offset.0 as usize - current_offest;
                for _ in 0..pre_padding {
                    output.write_all(&[0u8])?;
                }

                output.write_all(&section.content)?;
            }
        }

        assert_eq!(output.len(), layout.section_content_end_offset);

        Ok(output)
    }
}

fn write_pod<T: Pod>(data: &T, output: &mut Vec<u8>) {
    let data = std::slice::from_ref(data);
    write_pod_slice(data, output);
}

fn write_pod_slice<T: Pod>(data: &[T], output: &mut Vec<u8>) {
    let data = bytemuck::cast_slice::<T, u8>(data);
    output.extend(data);
}

/// Align a number `n` to `align`, increasing `n` if needed. `align` must be a power of two.
fn align_up(n: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());

    // n=0b0101, align=0b0100
    let required_mask = align - 1; // 0b0011
    let masked = n & required_mask; // 0b0001

    if masked == 0 {
        return n;
    }

    let next_down = n - masked; // 0b0100
    let ret = next_down + align; // 0b0110
    debug_assert!(ret >= n);
    debug_assert!(ret & align == 0);
    ret
}

#[cfg(test)]
mod tests {
    use super::align_up;

    #[test]
    fn align_up_correct() {
        assert_eq!(align_up(0b0101, 0b0010), 0b0110);
        assert_eq!(align_up(16, 8), 16);
        assert_eq!(align_up(15, 8), 16);
        assert_eq!(align_up(14, 8), 16);
        assert_eq!(align_up(11, 8), 16);
        assert_eq!(align_up(10, 8), 16);
        assert_eq!(align_up(9, 8), 16);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(0, 1), 0);
    }
}
