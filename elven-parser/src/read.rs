//! Structures and parsers for ELF64. ELF32 can knock itself out.
//!
//! See <https://man7.org/linux/man-pages/man5/elf.5.html>

use crate::{
    consts::{self as c, DynamicTag, ShType},
    idx::{define_idx, ElfIndexExt, ToIdxUsize},
    Addr, Offset, write::Section,
};
use bstr::BStr;

use std::{
    fmt::{Debug, Display},
    mem,
    string::{self, FromUtf8Error},
};

use bytemuck::{Pod, PodCastError, Zeroable};

#[derive(Debug, Clone, thiserror::Error)]
pub enum ElfReadError {
    #[error("The file is too small for the header")]
    FileTooSmall,
    #[error("An index into {2} is out of bounds. Expected at least {0} bytes, found {1} bytes")]
    RegionOutOfBounds(usize, usize, String),
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
    #[error("The {0} section was not found")]
    SectionTypeNotFound(ShType),
    #[error("The {0} with the name {1:?} was not found")]
    NotFoundByName(&'static str, std::result::Result<String, Vec<u8>>),
    #[error("Dynamic entry not found: {0}")]
    DynEntryNotFound(DynamicTag),
}

pub type Result<T> = std::result::Result<T, ElfReadError>;

define_idx! {
    pub struct ShStringIdx(u32);
}

define_idx! {
    pub struct StringIdx(u32);
}

define_idx! {
    pub struct SymIdx(u32);
}

/// A raw ELF. Does not come with cute ears for now.
#[derive(Debug, Clone, Copy)]
pub struct ElfReader<'a> {
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub r#type: c::Type,
    pub machine: c::Machine,
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
    pub shstrndex: c::SectionIdx,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfIdent {
    pub magic: [u8; c::SELFMAG],
    pub class: c::Class,
    pub data: c::Data,
    pub version: u8,
    pub osabi: c::OsAbi,
    pub abiversion: u8,
    pub _pad: [u8; 7],
}

const _: [u8; c::EI_NIDENT] = [0; mem::size_of::<ElfIdent>()];

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Phdr {
    pub r#type: c::PhType,
    pub flags: c::PhFlags,
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
    pub name: ShStringIdx,
    pub r#type: c::ShType,
    pub flags: c::ShFlags,
    pub addr: Addr,
    pub offset: Offset,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Sym {
    pub name: StringIdx,
    pub info: SymInfo,
    pub other: c::SymbolVisibility,
    pub shndx: c::SectionIdx,
    pub value: Addr,
    pub size: u64,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct SymInfo(pub u8);

impl SymInfo {
    pub fn r#type(self) -> c::SymbolType {
        c::SymbolType(self.0 & 0xf)
    }

    pub fn binding(self) -> c::SymbolBinding {
        c::SymbolBinding(self.0 >> 4)
    }
}

impl Debug for SymInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?},{:?}", self.r#type(), self.binding())
    }
}

impl Display for SymInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?},{:?}", self.r#type(), self.binding())
    }
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Rel {
    pub offset: Addr,
    pub info: RelInfo,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Rela {
    pub offset: Addr,
    pub info: RelInfo,
    pub addend: i64,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct RelInfo(pub u64);

impl RelInfo {
    pub fn sym(&self) -> SymIdx {
        SymIdx((self.0 >> 32) as u32)
    }

    pub fn r#type(&self) -> u32 {
        (self.0 & 0xffff_ffff) as u32
    }
}

impl Debug for RelInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} @ {}", c::RX86_64(self.r#type()), self.sym().0)
    }
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Dyn {
    pub tag: c::DynamicTag,
    pub val: u64,
}

impl<'a> ElfReader<'a> {
    /// Create a new elf reader. This only checks the elf magic but doens't do any parsing.
    /// The input slice `data` must be aligned to 8 bytes, otherwise the reader may panic later.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < mem::size_of::<ElfHeader>() {
            return Err(ElfReadError::FileTooSmall);
        }

        let magic = data[..c::SELFMAG].try_into().map_err(|_| {
            let mut padded = [0, 0, 0, 0];
            padded.copy_from_slice(data);
            ElfReadError::WrongMagic(padded)
        })?;

        if magic != *c::ELFMAG {
            return Err(ElfReadError::WrongMagic(magic));
        }

        let elf = ElfReader { data };

        Ok(elf)
    }

    pub fn header(&self) -> Result<&'a ElfHeader> {
        load_ref(self.data, "header")
    }

    pub fn program_headers(&self) -> Result<&'a [Phdr]> {
        let header = self.header()?;

        if header.phnum == 0 {
            return Ok(&[]);
        }

        let expected_ent_size = mem::size_of::<Phdr>();
        let actual_ent_size = usize::from(header.phentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfReadError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }

        load_slice(
            self.data.get_elf(header.phoff.., "program header offset")?,
            header.phnum.into(),
            "program headers",
        )
    }

    pub fn section_headers(&self) -> Result<&'a [Shdr]> {
        let header = self.header()?;

        if header.shnum == 0 {
            return Ok(&[]);
        }

        let expected_ent_size = mem::size_of::<Shdr>();
        let actual_ent_size = usize::from(header.shentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfReadError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }
        load_slice(
            self.data.get_elf(header.shoff.., "section header offset")?,
            header.shnum.into(),
            "section headers",
        )
    }

    pub fn section_header(&self, idx: c::SectionIdx) -> Result<&'a Shdr> {
        let sections = self.section_headers()?;
        sections.get_elf(idx.usize(), "section number")
    }

    pub fn section_header_by_name(&self, name: &[u8]) -> Result<&'a Shdr> {
        let sections = self.section_headers()?;
        for sh in sections {
            if self.sh_string(sh.name)? == name {
                return Ok(sh);
            }
        }
        let name = name.to_vec();
        Err(ElfReadError::NotFoundByName(
            "section",
            string::String::from_utf8(name).map_err(FromUtf8Error::into_bytes),
        ))
    }

    pub fn section_header_by_type(&self, ty: u32) -> Result<&'a Shdr> {
        self.section_headers()?
            .iter()
            .find(|sh| sh.r#type == ty)
            .ok_or(ElfReadError::SectionTypeNotFound(ShType(ty)))
    }

    pub fn section_content(&self, sh: &Shdr) -> Result<&'a [u8]> {
        if sh.r#type.0 == c::SHT_NOBITS {
            return Ok(&[]);
        }

        self.data
            .get_elf(sh.offset.., "section offset")?
            .get_elf(..sh.size, "section size")
    }

    pub fn sh_str_table(&self) -> Result<&'a [u8]> {
        let header = self.header()?;
        let shstrndex = header.shstrndex;

        if shstrndex == c::SHN_UNDEF {
            return Err(ElfReadError::StrTableSectionNotPresent);
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

        let strtab_header = self.section_header(shstrndex)?;
        self.section_content(strtab_header)
    }

    pub fn str_table(&self) -> Result<&'a [u8]> {
        let sh = self.section_header_by_name(b".strtab")?;
        self.section_content(sh)
    }

    pub fn sh_string(&self, idx: ShStringIdx) -> Result<&'a BStr> {
        let str_table = self.sh_str_table()?;
        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfReadError::NoStringNulTerm(idx.to_idx_usize()))?;
        Ok(BStr::new(&indexed[..end]))
    }

    pub fn string(&self, idx: StringIdx) -> Result<&'a BStr> {
        let str_table = self.str_table()?;
        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfReadError::NoStringNulTerm(idx.to_idx_usize()))?;
        Ok(BStr::new(&indexed[..end]))
    }

    pub fn dyn_string(&self, idx: StringIdx) -> Result<&'a BStr> {
        let tab_addr = self.dyn_entry_by_tag(c::DT_STRTAB)?;
        let tab_sz = self.dyn_entry_by_tag(c::DT_STRSZ)?;

        let str_table = self
            .data
            .get_elf(tab_addr.val.., "dyn string table")?
            .get_elf(..tab_sz.val, "dyn string table size")?;

        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfReadError::NoStringNulTerm(idx.to_idx_usize()))?;
        Ok(BStr::new(&indexed[..end]))
    }

    pub fn relas(&self) -> Result<impl Iterator<Item = (&'a Shdr, &'a Rela)>> {
        Ok(self
            .section_headers()?
            .iter()
            .filter(|sh| sh.r#type == c::SHT_RELA)
            .map(|sh| {
                let content = self.section_content(sh)?;
                let relas = load_slice::<Rela>(
                    content,
                    content.len() / mem::size_of::<Rela>(),
                    "relocations",
                )?;
                Ok((sh, relas))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flat_map(|(sh, relas)| relas.iter().map(move |rela| (sh, rela))))
    }

    pub fn symbols(&self) -> Result<&'a [Sym]> {
        let sh = self.section_header_by_type(c::SHT_SYMTAB)?;

        let data = self.section_content(sh)?;

        load_slice(data, data.len() / mem::size_of::<Sym>(), "symbols")
    }

    pub fn symbol(&self, idx: SymIdx) -> Result<&'a Sym> {
        self.symbols()?.get_elf(idx, "symbol index")
    }

    pub fn symbol_by_name(&self, name: &[u8]) -> Result<&'a Sym> {
        for symbol in self.symbols()? {
            let sym_name = self.string(symbol.name)?;
            if sym_name == name {
                return Ok(symbol);
            }
        }

        Err(ElfReadError::NotFoundByName(
            "symbol",
            string::String::from_utf8(name.to_vec()).map_err(FromUtf8Error::into_bytes),
        ))
    }

    pub fn dyn_symbols(&self) -> Result<&'a [Sym]> {
        let addr = self.dyn_entry_by_tag(c::DT_SYMTAB)?;
        let size = self.dyn_entry_by_tag(c::DT_SYMENT)?;

        dbg!(addr, size);

        let data = self.dyn_content(addr.val, size.val)?;

        load_slice(data, data.len() / mem::size_of::<Sym>(), "dyn symbols")
    }

    pub fn dyn_symbol(&self, idx: SymIdx) -> Result<&'a Sym> {
        dbg!(self.dyn_symbols()?).get_elf(idx, "symbol index")
    }

    pub fn dyn_entries(&self) -> Result<&'a [Dyn]> {
        let sh = self.section_header_by_name(b".dynamic")?;
        let data = self.section_content(sh)?;

        load_slice(data, data.len() / mem::size_of::<Dyn>(), "dyn entries")
    }

    pub fn dyn_entry_by_tag(&self, tag: u64) -> Result<&'a Dyn> {
        self.dyn_entries()?
            .iter()
            .find(|dy| dy.tag == tag)
            .ok_or(ElfReadError::DynEntryNotFound(DynamicTag(tag)))
    }

    pub fn dyn_content(&self, addr: u64, size: u64) -> Result<&'a [u8]> {
        self.data
            .get_elf(addr.., "dyn content offset")?
            .get_elf(..size, "section size")
    }
}

fn load_ref<'a, T: Pod>(data: &'a [u8], kind: impl Into<String>) -> Result<&'a T> {
    load_slice(data, 1, kind).map(|slice| &slice[0])
}

pub(crate) fn load_slice<'a, T: Pod>(
    data: &'a [u8],
    amount_of_elems: usize,
    kind: impl Into<String>,
) -> Result<&'a [T]> {
    let size = mem::size_of::<T>() * amount_of_elems;
    let align = mem::align_of::<T>();

    if data.len() < size {
        return Err(ElfReadError::RegionOutOfBounds(
            size,
            data.len(),
            kind.into(),
        ));
    }

    let data_addr = (data as *const [u8]).cast::<u8>() as usize;
    let data_align = data_addr.trailing_zeros() as usize;

    let data = &data[..size];

    bytemuck::try_cast_slice::<_, T>(data).map_err(|e| match e {
        e @ (PodCastError::SizeMismatch
        | PodCastError::OutputSliceWouldHaveSlop
        | PodCastError::AlignmentMismatch) => {
            unreachable!("already checked for these errors: {e}")
        }
        PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
            ElfReadError::UnalignedInput(align, data_align)
        }
    })
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
        let elf = ElfReader::new(&file)?;
        let header = elf.header()?;

        assert_eq!(header.ident.class, c::ELFCLASS64);
        assert_eq!(header.ident.data, c::ELFDATA2LSB);
        assert_eq!(header.ident.osabi, c::ELFOSABI_SYSV);
        assert_eq!(header.r#type, c::ET_DYN);
        assert_ne!(header.entry, Addr(0));

        elf.program_headers()?;
        elf.section_headers()?;

        for section in elf.section_headers()? {
            let name = elf.sh_string(section.name)?.to_string();
            println!("{name:20} {:5} {:?}", section.size, section.r#type);
        }

        Ok(())
    }

    #[test]
    fn c_hello_world_object() -> super::Result<()> {
        let file = load_test_file("hello_world_obj.o");
        let elf = ElfReader::new(&file)?;
        let header = elf.header()?;

        assert_eq!(header.ident.class, c::ELFCLASS64);
        assert_eq!(header.ident.data, c::ELFDATA2LSB);
        assert_eq!(header.ident.osabi, c::ELFOSABI_SYSV);
        assert_eq!(header.r#type, c::ET_REL);
        assert_eq!(header.entry, Addr(0));

        elf.program_headers()?;
        elf.section_headers()?;

        println!("Sections:\n");

        for sh in elf.section_headers()? {
            let name = elf.sh_string(sh.name)?.to_string();
            println!("{name:20} {:5} {:?}", sh.size, sh.r#type);
        }

        println!("Relocations:\n");

        println!("{:20} {:10} {}", "Section", "Symbol", "Relocation");

        let mut has_puts = false;
        for (sh, rela) in elf.relas()? {
            let section_name = elf.sh_string(sh.name)?.to_string();
            let sym = elf.symbol(rela.info.sym())?;
            let sym_name = elf.string(sym.name)?.to_string();
            println!("{section_name:20} {sym_name:10} {rela:?}");

            if sym_name == "puts" {
                has_puts = true;
            }
        }

        assert!(has_puts, "puts symbol not found");

        Ok(())
    }
}
