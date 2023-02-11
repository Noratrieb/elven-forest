//! Structures and parsers for ELF64. ELF32 can knock itself out.

use std::mem;

#[derive(Debug)]
pub struct Addr(u64);
#[derive(Debug)]
pub struct Offset(u64);
#[derive(Debug)]
pub struct Section(u16);
#[derive(Debug)]
pub struct Versym(u16);

#[derive(Debug, Clone, thiserror::Error)]
pub enum ElfParseError {
    #[error("The file is too small. Expected at least {0} bytes, found {1} bytes")]
    FileTooSmall(usize, usize),
    #[error("The input is not aligned in memory. Expected align {0}, found align {1}")]
    UnalignedInput(usize, usize),
    #[error("The magic of the file did not match. Maybe it's not an ELF file?. Found {0:x?}")]
    WrongMagic([u8; 4]),
}

/// A raw ELF. Does not come with cute ears for now.
#[derive(Debug)]
pub struct Elf<'a> {
    pub header: &'a ElfHeader,
}

#[derive(Debug)]
#[repr(C)]
pub struct ElfHeader {
    pub ident: [u8; 16],
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

impl<'a> Elf<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, ElfParseError> {
        const HEADER_SIZE: usize = mem::size_of::<ElfHeader>();
        const HEADER_ALIGN: usize = mem::align_of::<ElfHeader>();

        if input.len() < HEADER_SIZE {
            return Err(ElfParseError::FileTooSmall(HEADER_SIZE, input.len()));
        }

        let input_ptr = input as *const [u8];

        let input_addr = input_ptr as *const u8 as usize;
        let align = input_addr.trailing_zeros() as usize;

        if align < HEADER_ALIGN {
            return Err(ElfParseError::UnalignedInput(HEADER_ALIGN, align));
        }

        let header = input_ptr as *const ElfHeader;
        // SAFETY: We checked that the size is enough. We checked that the alignment matches.
        // ElfHeader is POD.
        let header = unsafe { &*header };

        let magic = header.ident[..4].try_into().unwrap();

        if magic != [0x7f, b'E', b'L', b'F'] {
            return Err(ElfParseError::WrongMagic(magic));
        }

        Ok(Elf { header })
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
    fn rust_hello_world_bin() {
        let file = load_test_file("hello_world");
        let elf = Elf::parse(&file).unwrap();
        dbg!(elf);
        panic!()
    }
}
