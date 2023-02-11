//! Structures and parsers for ELF64. ELF32 can knock itself out.
//!
//! See https://man7.org/linux/man-pages/man5/elf.5.html

use crate::{
    consts as c,
    idx::{define_idx, ElfIndexExt, ToIdxUsize},
    ElfParseError, Result,
};
use bstr::BStr;

use std::{fmt::Debug, mem, string};

use bytemuck::{Pod, PodCastError, Zeroable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]

pub struct Addr(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Offset(pub u64);

impl ToIdxUsize for Offset {
    fn to_idx_usize(self) -> usize {
        self.0 as usize
    }
}

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
    pub name: ShStringIdx,
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
    pub addend: u64,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct RelInfo(pub u64);

impl RelInfo {
    pub fn sym(&self) -> SymIdx {
        SymIdx((self.0 >> 32) as u32)
    }

    pub fn r#type(&self) -> u32 {
        (self.0 & 0xffffffff) as u32
    }
}

impl Debug for RelInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} @ {}", c::RX86_64(self.r#type()), self.sym().0)
    }
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

        if header.phnum == 0 {
            return Ok(&[]);
        }

        let expected_ent_size = mem::size_of::<Phdr>();
        let actual_ent_size = usize::from(header.phentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfParseError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }

        load_slice(
            self.data.get_elf(header.phoff.., "program header offset")?,
            header.phnum.into(),
        )
    }

    pub fn section_headers(&self) -> Result<&[Shdr]> {
        let header = self.header()?;

        if header.shnum == 0 {
            return Ok(&[]);
        }

        let expected_ent_size = mem::size_of::<Shdr>();
        let actual_ent_size = usize::from(header.shentsize);
        if actual_ent_size != expected_ent_size {
            return Err(ElfParseError::InvalidPhEntSize(
                expected_ent_size,
                actual_ent_size,
            ));
        }
        load_slice(
            self.data.get_elf(header.shoff.., "sectoin header offset")?,
            header.shnum.into(),
        )
    }

    pub fn section_header(&self, idx: c::SectionIdx) -> Result<&Shdr> {
        let sections = self.section_headers()?;
        sections.get_elf(idx.usize(), "section number")
    }

    pub fn section_header_by_name(&self, name: &[u8]) -> Result<&Shdr> {
        let sections = self.section_headers()?;
        for sh in sections {
            if self.sh_string(sh.name)? == name {
                return Ok(sh);
            }
        }
        let name = name.to_vec();
        Err(ElfParseError::SectionNotFound(
            string::String::from_utf8(name).map_err(|err| err.into_bytes()),
        ))
    }

    pub fn section_content(&self, sh: &Shdr) -> Result<&[u8]> {
        if sh.r#type.0 == c::SHT_NOBITS {
            return Ok(&[]);
        }

        self.data
            .get_elf(sh.offset.., "section offset")?
            .get_elf(..sh.size, "section size")
    }

    pub fn sh_str_table(&self) -> Result<&[u8]> {
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

        let strtab_header = self.section_header(shstrndex)?;
        self.section_content(strtab_header)
    }

    pub fn str_table(&self) -> Result<&[u8]> {
        let sh = self.section_header_by_name(b".strtab")?;
        self.section_content(sh)
    }

    pub fn sh_string(&self, idx: ShStringIdx) -> Result<&BStr> {
        let str_table = self.sh_str_table()?;
        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfParseError::NoStringNulTerm(idx.to_idx_usize()))?;
        Ok(BStr::new(&indexed[..end]))
    }

    pub fn string(&self, idx: StringIdx) -> Result<&BStr> {
        let str_table = self.str_table()?;
        let indexed = str_table.get_elf(idx.., "string offset")?;
        let end = indexed
            .iter()
            .position(|&c| c == b'\0')
            .ok_or(ElfParseError::NoStringNulTerm(idx.to_idx_usize()))?;
        Ok(BStr::new(&indexed[..end]))
    }

    pub fn relas(&self) -> Result<impl Iterator<Item = (&Shdr, &Rela)>> {
        Ok(self
            .section_headers()?
            .iter()
            .filter(|sh| sh.r#type == c::SHT_RELA)
            .map(|sh| {
                let content = self.section_content(sh)?;
                let relas = load_slice::<Rela>(content, content.len() / mem::size_of::<Rela>())?;
                Ok((sh, relas))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flat_map(|(sh, relas)| relas.iter().map(move |rela| (sh, rela))))
    }

    pub fn symbols(&self) -> Result<&[Sym]> {
        let sh = self
            .section_headers()?
            .iter()
            .find(|sh| sh.r#type == c::SHT_SYMTAB)
            .ok_or(ElfParseError::SymtabNotFound)?;

        let data = self.section_content(sh)?;

        load_slice(data, data.len() / mem::size_of::<Sym>())
    }

    pub fn symbol(&self, idx: SymIdx) -> Result<&Sym> {
        self.symbols()?.get_elf(idx, "symbol index")
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
            let name = elf.sh_string(section.name)?.to_string();
            println!("{name:20} {:5} {:?}", section.size, section.r#type);
        }

        Ok(())
    }

    #[test]
    fn c_hello_world_object() -> super::Result<()> {
        let file = load_test_file("hello_world_obj");
        let elf = Elf::new(&file)?;
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
