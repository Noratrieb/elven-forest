//! Structures and parsers for ELF64. ELF32 can knock itself out.
//!
//! See https://man7.org/linux/man-pages/man5/elf.5.html

pub mod consts;
use consts as c;

use std::{ffi::CStr, fmt::Debug, mem, ops, slice::SliceIndex};

use bytemuck::{Pod, PodCastError, Zeroable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]

pub struct Addr(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Offset(pub u64);

impl Offset {
    fn usize(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Section(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Versym(pub u16);

#[derive(Debug, Clone, thiserror::Error)]
pub enum ElfParseError {
    #[error("The file is too small. Expected at least {0} bytes, found {1} bytes")]
    FileTooSmall(usize, usize),
    #[error("The input is not aligned in memory. Expected align {0}, found align {1}")]
    UnalignedInput(usize, usize),
    #[error("The magic of the file did not match. Maybe it's not an ELF file?. Found {0:x?}")]
    WrongMagic([u8; 4]),
    #[error("A program header entry has a different size than expected. Expected {0}, found {1}")]
    InvalidPhEntSize(usize, usize),
    #[error("A section header entry has a different size than expected. Expected {0}, found {1}")]
    InvalidShEntSize(usize, usize),
    #[error("The string table section is marked as UNDEF")]
    StrTableSectionNotPresent,
    #[error("An index is out of bounds: {0}: {1}")]
    IndexOutOfBounds(&'static str, usize),
    #[error("String in string table does not end with a nul terminator: String offset: {0}")]
    NoStringNulTerm(usize),
}

type Result<T> = std::result::Result<T, ElfParseError>;

/// A raw ELF. Does not come with cute ears for now.
#[derive(Debug)]
pub struct Elf<'a> {
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub r#type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: Addr,
    pub phoff: Offset,
    pub shoff: Offset,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndex: u16,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfIdent {
    magic: [u8; c::SELFMAG],
    class: u8,
    data: u8,
    version: u8,
    osabi: u8,
    abiversion: u8,
    _pad: [u8; 7],
}

const _: [u8; c::EI_NIDENT] = [0; mem::size_of::<ElfIdent>()];

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Phdr {
    pub r#type: u32,
    pub flags: u32,
    pub offset: Offset,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Shdr {
    pub name: u32,
    pub r#type: c::ShType,
    pub flags: u64,
    pub addr: Addr,
    pub offset: Offset,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

impl<'a> Elf<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let magic = data[..c::SELFMAG].try_into().unwrap();

        if magic != *c::ELFMAG {
            return Err(ElfParseError::WrongMagic(magic));
        }

        let elf = Elf { data };

        Ok(elf)
    }

    pub fn header(&self) -> Result<&ElfHeader> {
        load_ref(self.data)
    }

    pub fn program_headers(&self) -> Result<&[Phdr]> {
        let header = self.header()?;

        let expected_ent_size = mem::size_of::<Phdr>();
        let actual_ent_size = usize::from(header.phentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfParseError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }

        let off = header.phoff.usize();
        load_slice(
            &self.data.get_elf(off.., "program header offset")?,
            header.phnum.into(),
        )
    }

    pub fn section_headers(&self) -> Result<&[Shdr]> {
        let header = self.header()?;

        let expected_ent_size = mem::size_of::<Shdr>();
        let actual_ent_size = usize::from(header.shentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfParseError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }
        let off = header.shoff.usize();
        load_slice(
            &self.data.get_elf(off.., "sectoin header offset")?,
            header.shnum.into(),
        )
    }

    pub fn section_header(&self, idx: usize) -> Result<&Shdr> {
        let sections = self.section_headers()?;
        sections.get_elf(idx, "section number")
    }

    pub fn section_content(&self, sh: &Shdr) -> Result<&[u8]> {
        if sh.r#type.0 == c::SHT_NOBITS {
            return Ok(&[]);
        }

        Ok(&self
            .data
            .get_elf(sh.offset.usize().., "section offset")?
            .get_elf(..(sh.size as usize), "section size")?)
    }

    pub fn str_table(&self) -> Result<&[u8]> {
        let header = self.header()?;
        let shstrndex = header.shstrndex;

        if shstrndex == c::SHN_UNDEF {
            return Err(ElfParseError::StrTableSectionNotPresent);
        }

        if shstrndex >= c::SHN_LORESERVE {
            todo!(
                "the real index of the
            section name string table section is held in the sh_link
            member of the initial entry in section header table.
            Otherwise, the sh_link member of the initial entry in
            section header table contains the value zero."
            )
        }

        let strtab_header = self.section_header(shstrndex as usize)?;
        self.section_content(strtab_header)
    }

    pub fn string(&self, idx: usize) -> Result<&CStr> {
        let str_table = self.str_table()?;
        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfParseError::NoStringNulTerm(idx))?;
        Ok(CStr::from_bytes_with_nul(&indexed[..=end]).unwrap())
    }
}

fn load_ref<T: Pod>(data: &[u8]) -> Result<&T> {
    load_slice(data, 1).map(|slice| &slice[0])
}

fn load_slice<T: Pod>(data: &[u8], amount_of_elems: usize) -> Result<&[T]> {
    let size = mem::size_of::<T>() * amount_of_elems;
    let align = mem::align_of::<T>();

    if data.len() < size {
        return Err(ElfParseError::FileTooSmall(size, data.len()));
    }

    let data_addr = data as *const [u8] as *const u8 as usize;
    let data_align = data_addr.trailing_zeros() as usize;

    let data = &data[..size];

    bytemuck::try_cast_slice::<_, T>(data).map_err(|e| match e {
        e @ (PodCastError::SizeMismatch
        | PodCastError::OutputSliceWouldHaveSlop
        | PodCastError::AlignmentMismatch) => {
            unreachable!("already checked for these errors: {e}")
        }
        PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
            ElfParseError::UnalignedInput(align, data_align)
        }
    })
}

trait ElfIndex<T: ?Sized>: SliceIndex<T> {
    fn bound(&self) -> usize;
}

impl<T> ElfIndex<[T]> for usize {
    fn bound(&self) -> usize {
        *self
    }
}

impl<T> ElfIndex<[T]> for ops::RangeFrom<usize> {
    fn bound(&self) -> usize {
        self.start
    }
}

impl<T> ElfIndex<[T]> for ops::RangeTo<usize> {
    fn bound(&self) -> usize {
        self.end
    }
}

trait ElfIndexExt {
    fn get_elf<I: ElfIndex<Self>>(&self, idx: I, msg: &'static str) -> Result<&I::Output>;
}

impl<T> ElfIndexExt for [T] {
    fn get_elf<I: ElfIndex<Self>>(&self, idx: I, msg: &'static str) -> Result<&I::Output> {
        let bound = idx.bound();
        self.get(idx)
            .ok_or(ElfParseError::IndexOutOfBounds(msg, bound))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use memmap2::Mmap;

    use super::*;

    fn load_test_file(file_name: impl AsRef<Path>) -> Mmap {
        let name = file_name.as_ref();
        let this_file_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file!());
        let double_this_crate = this_file_path.parent().unwrap().parent().unwrap();
        let workspace_root = double_this_crate.parent().unwrap().parent().unwrap();

        let file_path = workspace_root.join("test_data").join("out").join(name);

        let file = fs::File::open(&file_path).expect(&format!(
            "Failed to open test file {} at path {}. Consider running `test_data/create_test_data.sh` to create the test data files",
            name.display(),
            file_path.display()
        ));

        unsafe { Mmap::map(&file).unwrap() }
    }

    #[test]
    fn rust_hello_world_bin() -> super::Result<()> {
        let file = load_test_file("hello_world");
        let elf = Elf::new(&file)?;
        let header = elf.header()?;

        assert_eq!(header.ident.class, c::ELFCLASS64);
        assert_eq!(header.ident.data, c::ELFDATA2LSB);
        assert_eq!(header.ident.osabi, c::ELFOSABI_SYSV);
        assert_eq!(header.r#type, c::ET_DYN);
        assert_ne!(header.entry, Addr(0));

        elf.program_headers()?;
        elf.section_headers()?;

        for section in elf.section_headers()? {
            let name = elf.string(section.name as usize)?.to_str().unwrap();
            println!("{name:20} {:5} {:?}", section.size, section.r#type);
        }

        Ok(())
    }
}
