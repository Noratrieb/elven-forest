pub mod consts;
pub mod defs;
mod idx;

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
    #[error("The SHT_SYMTAB section was not found")]
    SymtabNotFound,
    #[error("The section with the name {0:?} was not found")]
    SectionNotFound(std::result::Result<String, Vec<u8>>),
}

pub type Result<T> = std::result::Result<T, ElfParseError>;
