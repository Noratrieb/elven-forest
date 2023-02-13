use crate::consts::{Machine, PhFlags, PhType, SectionIdx, ShType, Type, SHT_NULL, SHT_STRTAB};
use crate::read::{self, Addr, ElfIdent, Offset, ShStringIdx};
use std::io;
use std::mem::size_of;
use std::num::NonZeroU64;

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
        };

        let shstrtab = Section {
            // The first string which happens to be .shstrtab below.
            name: read::ShStringIdx(1),
            r#type: ShType(SHT_STRTAB),
            flags: 0,
            // Set up the null string and also the .shstrtab, our section.
            content: b"\0.shstrtab\0".to_vec(),
            fixed_entsize: None,
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

mod writing {
    use bytemuck::Pod;

    use super::{ElfWriter, Result, WriteElfError};
    use crate::read::{Addr, ElfHeader, Offset, Phdr, Shdr};
    use std::{io::Write, mem::size_of, num::NonZeroU64};

    const SH_OFFSET_OFFSET: usize = memoffset::offset_of!(Shdr, offset);

    impl ElfWriter {
        pub fn write(&self) -> Result<Vec<u8>> {
            let mut output = Vec::new();

            let mut current_known_position = 0;

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

            // We know the size of the header.
            current_known_position += size_of::<ElfHeader>() as u64;

            // ld orderes it ph/sh apparently so we will do the same

            if !self.programs_headers.is_empty() {
                header.phoff = Offset(current_known_position);
            }

            // There will be all the program headers right after the header.
            let program_headers_start = current_known_position;
            let all_ph_size = (header.phentsize as u64) * (header.phnum as u64);
            current_known_position += all_ph_size;

            if !self.sections.is_empty() {
                header.shoff = Offset(current_known_position);
            }

            // There will be all the section headers right after the program headers.
            let section_headers_start = current_known_position;
            let section_headers_size = header.shentsize as u64 * header.shnum as u64;
            current_known_position += section_headers_size;

            write_pod(&header, &mut output);

            // Reserve some space for the program headers
            output.extend(std::iter::repeat(0).take(all_ph_size as usize));

            for section in &self.sections {
                let header = Shdr {
                    name: section.name,
                    r#type: section.r#type,
                    flags: section.flags,
                    addr: Addr(0),
                    offset: Offset(current_known_position),
                    size: section.content.len() as u64,
                    link: 0,
                    info: 0,
                    addralign: 0,
                    entsize: section.fixed_entsize.map(NonZeroU64::get).unwrap_or(0),
                };

                // We will write the content for this section at that offset and also make sure to align the next one.
                // FIXME: Align to the alignment of the next section.
                current_known_position += align_up(section.content.len() as u64, 8);

                write_pod(&header, &mut output);
            }

            for section in &self.sections {
                let section_size = section.content.len() as u64;
                let aligned_size = align_up(section_size, 8);
                let padding = aligned_size - section_size;

                output.write_all(&section.content)?;
                for _ in 0..padding {
                    output.write_all(&[0u8])?;
                }
            }

            // We know have a few clues about section offsets, so write the program headers.
            for (i, program_header) in self.programs_headers.iter().enumerate() {
                let rel_offset = program_header.offset;
                let section_base_offset = section_headers_start as usize
                    + header.shentsize as usize * rel_offset.section.0 as usize;

                let section_offset_offset = section_base_offset + SH_OFFSET_OFFSET;
                let section_content_offset_bytes = output[section_offset_offset..]
                    [..size_of::<u64>()]
                    .try_into()
                    .unwrap();
                let section_content_offset = u64::from_ne_bytes(section_content_offset_bytes);

                let offset = Offset(section_content_offset + rel_offset.rel_offset.0);

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

                let program_header_start =
                    program_headers_start as usize + header.phentsize as usize * i as usize;
                let space = &mut output[program_header_start..][..header.phentsize as usize];
                let ph_bytes = bytemuck::cast_slice::<Phdr, u8>(std::slice::from_ref(&ph));

                space.copy_from_slice(ph_bytes);

                write_pod(&ph, &mut output);
            }

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

    fn align_up(n: u64, align: u64) -> u64 {
        // n=0b0101, align=0b0100
        let required_mask = align - 1; // 0b0011
        let masked = n & required_mask; // 0b0001

        if masked == 0 {
            return n;
        }

        let next_down = n - masked; // 0b0100
        next_down + align // 0b0110
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
}
