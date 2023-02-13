use crate::consts::{Machine, SectionIdx, ShType, Type, SHT_NULL, SHT_STRTAB};
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
    entry: SectionRelativeAbsoluteAddr,
    sections_headers: Vec<Section>,
    programs_headers: Vec<ProgramHeader>,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub ident: ElfIdent,
    pub r#type: Type,
    pub machine: Machine,
}

#[derive(Debug, Clone)]
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
pub struct ProgramHeader {}

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
            entry: SectionRelativeAbsoluteAddr {
                section: SectionIdx(0),
                rel_offset: Offset(0),
            },
            sections_headers: vec![null_section, shstrtab],
            programs_headers: Vec::new(),
        }
    }

    pub fn set_entry(&mut self, entry: SectionRelativeAbsoluteAddr) {
        self.entry = entry;
    }

    pub fn add_sh_string(&mut self, content: &[u8]) -> ShStringIdx {
        let shstrtab = &mut self.sections_headers[SH_STRTAB];
        let idx = shstrtab.content.len();
        shstrtab.content.extend(content);
        shstrtab.content.push(0);
        ShStringIdx(idx as u32)
    }

    pub fn add_section(&mut self, section: Section) {
        self.sections_headers.push(section);
    }
}

mod writing {
    use bytemuck::Pod;

    use crate::read::{Addr, ElfHeader, Offset, Shdr, HEADER_ENTRY_OFFSET};
    use std::{io::Write, mem::size_of, num::NonZeroU64};

    use super::{ElfWriter, Result, WriteElfError};

    impl ElfWriter {
        pub fn write(&self) -> Result<Vec<u8>> {
            let mut output = Vec::new();

            let mut current_known_position = 0;

            let mut header = self.header;

            header.shnum = self
                .sections_headers
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

            // We put the section headers directly after the header.
            if !self.sections_headers.is_empty() {
                header.shoff = Offset(current_known_position);
            }

            // There will be all the section headers right after the header.
            current_known_position += (header.shentsize * header.shnum) as u64;

            // We put the program headers directly after the section headers.
            if !self.programs_headers.is_empty() {
                header.phoff = Offset(current_known_position);
            }

            // There will be all the program headers right after the section headers.
            current_known_position += (header.phentsize * header.phnum) as u64;

            write_pod(&header, &mut output);

            for (sh_idx, section) in self.sections_headers.iter().enumerate() {
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

                if sh_idx == self.entry.section.0 as usize {
                    let base = current_known_position;
                    let entry = base + self.entry.rel_offset.0;
                    let entry_pos = &mut output[HEADER_ENTRY_OFFSET..][..size_of::<u64>()];
                    let entry_ref = bytemuck::cast_slice_mut::<u8, u64>(entry_pos);
                    entry_ref[0] = entry;
                }

                // We will write the content for this section at that offset and also make sure to align the next one.
                // FIXME: Align to the alignment of the next section.
                current_known_position += align_up(section.content.len() as u64, 8);

                write_pod(&header, &mut output);
            }

            assert_eq!(self.programs_headers.len(), 0); // FIXME: yeah

            for section in &self.sections_headers {
                let section_size = section.content.len() as u64;
                let aligned_size = align_up(section_size, 8);
                let padding = aligned_size - section_size;

                output.write_all(&section.content)?;
                for _ in 0..padding {
                    output.write_all(&[0u8])?;
                }
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
