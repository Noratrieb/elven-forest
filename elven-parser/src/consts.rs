#![allow(non_upper_case_globals)]

macro_rules! const_group_with_fmt {
    (
        pub struct $struct_name:ident($ty:ty): $group_name:literal

        $(
            pub const $name:ident = $value:expr;
        )*
    ) => {
        $(
            pub const $name: $ty = $value;
        )*

        #[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
        #[repr(transparent)]
        pub struct $struct_name(pub $ty);

        impl std::fmt::Debug for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    $(
                        $value => f.write_str(stringify!($name)),
                    )*
                    a => write!(f, "{}({a})", $group_name)
                }
            }
        }

        impl std::fmt::Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    $(
                        $value => f.write_str(stringify!($name)),
                    )*
                    a => write!(f, "{}({a})", $group_name)
                }
            }
        }


        impl PartialEq<$ty> for $struct_name {
            fn eq(&self, other: &$ty) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$struct_name> for $ty {
            fn eq(&self, other: &$struct_name) -> bool {
               *self == other.0
            }
        }

        impl PartialOrd<$ty> for $struct_name {
            fn partial_cmp(&self, other: &$ty) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }

        impl PartialOrd<$struct_name> for $ty {
            fn partial_cmp(&self, other: &$struct_name) -> Option<std::cmp::Ordering> {
                self.partial_cmp(&other.0)
            }
        }
    };
}

// ------------------
// Header
// ------------------

/* Conglomeration of the identification bytes, for easy testing as a word.  */
pub const ELFMAG: &[u8; SELFMAG] = b"\x7fELF";
pub const SELFMAG: usize = 4;

pub const EI_CLASS: usize = 4; /* File class byte index */
const_group_with_fmt! {
    pub struct Class(u8): "class"

    pub const ELFCLASSNONE = 0; /* Invalid class */
    pub const ELFCLASS32 = 1; /* 32-bit objects */
    pub const ELFCLASS64 = 2; /* 64-bit objects */
}
pub const ELFCLASSNUM: u8 = 3;

pub const EI_DATA: usize = 5; /* Data encoding byte index */
const_group_with_fmt! {
    pub struct Data(u8): "data"

    pub const ELFDATANONE = 0; /* Invalid data encoding */
    pub const ELFDATA2LSB = 1; /* 2's complement, little endian */
    pub const ELFDATA2MSB = 2; /* 2's complement, big endian */
}
pub const ELFDATANUM: u8 = 3;

pub const EI_VERSION: usize = 6; /* File version byte index */

pub const EI_OSABI: usize = 7; /* OS ABI identification */
const_group_with_fmt! {
    pub struct OsAbi(u8): "OS ABI"

    pub const ELFOSABI_SYSV = 0; /* Alias.  */
    pub const ELFOSABI_HPUX = 1; /* HP-UX */
    pub const ELFOSABI_NETBSD = 2; /* NetBSD.  */
    pub const ELFOSABI_GNU = 3; /* Object uses GNU ELF extensions.  */
    pub const ELFOSABI_SOLARIS = 6; /* Sun Solaris.  */
    pub const ELFOSABI_AIX = 7; /* IBM AIX.  */
    pub const ELFOSABI_IRIX = 8; /* SGI Irix.  */
    pub const ELFOSABI_FREEBSD = 9; /* FreeBSD.  */
    pub const ELFOSABI_TRU64 = 10; /* Compaq TRU64 UNIX.  */
    pub const ELFOSABI_MODESTO = 11; /* Novell Modesto.  */
    pub const ELFOSABI_OPENBSD = 12; /* OpenBSD.  */
    pub const ELFOSABI_ARM_AEABI = 64; /* ARM EABI */
    pub const ELFOSABI_ARM = 97; /* ARM */
    pub const ELFOSABI_STANDALONE = 255; /* Standalone (embedded) application */
}
pub const ELFOSABI_NONE: u8 = 0; /* UNIX System V ABI */
pub const ELFOSABI_LINUX: u8 = 3; /* Compatibility alias.  */

pub const EI_ABIVERSION: usize = 8; /* ABI version */

pub const EI_PAD: usize = 9; /* Byte index of padding bytes */

pub const EI_NIDENT: usize = 16;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_NONE: u16 = 0; /* No machine */
pub const EM_X86_64: u16 = 62; /* AMD x86-64 architecture */

pub const EV_NONE: u32 = 0;

// ------------------
// Sections
// ------------------

const_group_with_fmt! {
    pub struct SectionIdx(u16): "SHN"

    pub const SHN_UNDEF = 0; /* Undefined section */
    pub const SHN_BEFORE = 0xff00; /* Order section before all others (Solaris).  */
    pub const SHN_AFTER = 0xff01; /* Order section after all others (Solaris).  */

    pub const SHN_ABS = 0xfff1; /* Associated symbol is absolute */
    pub const SHN_COMMON = 0xfff2; /* Associated symbol is common */
    pub const SHN_XINDEX = 0xffff; /* Index is in extra table.  */
}
pub const SHN_LORESERVE: u16 = 0xff00; /* Start of reserved indices */
pub const SHN_LOPROC: u16 = 0xff00; /* Start of processor-specific */
pub const SHN_HIPROC: u16 = 0xff1f; /* End of processor-specific */
pub const SHN_LOOS: u16 = 0xff20; /* Start of OS-specific */
pub const SHN_HIOS: u16 = 0xff3f; /* End of OS-specific */
pub const SHN_HIRESERVE: u16 = 0xffff; /* End of reserved indices */

const_group_with_fmt! {
    pub struct ShType(u32): "SHT"

    pub const SHT_NULL = 0; /* Section header table entry unused */
    pub const SHT_PROGBITS = 1; /* Program data */
    pub const SHT_SYMTAB = 2; /* Symbol table */
    pub const SHT_STRTAB = 3; /* String table */
    pub const SHT_RELA = 4; /* Relocation entries with addends */
    pub const SHT_HASH = 5; /* Symbol hash table */
    pub const SHT_DYNAMIC = 6; /* Dynamic linking information */
    pub const SHT_NOTE = 7; /* Notes */
    pub const SHT_NOBITS = 8; /* Program space with no data (bss) */
    pub const SHT_REL = 9; /* Relocation entries, no addends */
    pub const SHT_SHLIB = 10; /* Reserved */
    pub const SHT_DYNSYM = 11; /* Dynamic linker symbol table */
    pub const SHT_INIT_ARRAY = 14; /* Array of constructors */
    pub const SHT_FINI_ARRAY = 15; /* Array of destructors */
    pub const SHT_PREINIT_ARRAY = 16; /* Array of pre-constructors */
    pub const SHT_GROUP = 17; /* Section group */
    pub const SHT_SYMTAB_SHNDX = 18; /* Extended section indices */
    pub const SHT_NUM = 19; /* Number of defined types.  */
    pub const SHT_GNU_ATTRIBUTES = 0x6ffffff5; /* Object attributes.  */
    pub const SHT_GNU_HASH = 0x6ffffff6; /* GNU-style hash table.  */
    pub const SHT_GNU_LIBLIST = 0x6ffffff7; /* Prelink library list */
    pub const SHT_CHECKSUM = 0x6ffffff8; /* Checksum for DSO content.  */
    pub const SHT_SUNW_move = 0x6ffffffa;
    pub const SHT_SUNW_COMDAT = 0x6ffffffb;
    pub const SHT_SUNW_syminfo = 0x6ffffffc;
    pub const SHT_GNU_verdef = 0x6ffffffd; /* Version definition section.  */
    pub const SHT_GNU_verneed = 0x6ffffffe; /* Version needs section.  */
    pub const SHT_GNU_versym = 0x6fffffff; /* Version symbol table.  */
    pub const SHT_LOPROC = 0x70000000; /* Start of processor-specific */
    pub const SHT_HIPROC = 0x7fffffff; /* End of processor-specific */
    pub const SHT_LOUSER = 0x80000000; /* Start of application-specific */
    pub const SHT_HIUSER = 0x8fffffff; /* End of application-specific */
}

pub const SHT_LOOS: u32 = 0x60000000; /* Start OS-specific.  */
pub const SHT_LOSUNW: u32 = 0x6ffffffa; /* Sun-specific low bound.  */
pub const SHT_HISUNW: u32 = 0x6fffffff; /* Sun-specific high bound.  */
pub const SHT_HIOS: u32 = 0x6fffffff; /* End OS-specific type */

// ------------------
// Symbols
// ------------------

const_group_with_fmt! {
    pub struct SymbolType(u8): "STT"

    pub const STT_NOTYPE = 0; /* Symbol type is unspecified */
    pub const STT_OBJECT = 1; /* Symbol is a data object */
    pub const STT_FUNC = 2; /* Symbol is a code object */
    pub const STT_SECTION = 3; /* Symbol associated with a section */
    pub const STT_FILE = 4; /* Symbol's name is file name */
    pub const STT_COMMON = 5; /* Symbol is a common data object */
    pub const STT_TLS = 6; /* Symbol is thread-local data object*/
    pub const STT_NUM = 7; /* Number of defined types.  */
    pub const STT_GNU_IFUNC = 10; /* Symbol is indirect code object */
    pub const STT_HIOS = 12; /* End of OS-specific */
    pub const STT_LOPROC = 13; /* Start of processor-specific */
    pub const STT_HIPROC = 15; /* End of processor-specific */
}
pub const STT_LOOS: u32 = 10; /* Start of OS-specific */

const_group_with_fmt! {
    pub struct SymbolBinding(u8): "STB"

    pub const STB_LOCAL = 0; /* Local symbol */
    pub const STB_GLOBAL = 1; /* Global symbol */
    pub const STB_WEAK = 2; /* Weak symbol */
    pub const STB_NUM = 3; /* Number of defined types.  */
    pub const STB_GNU_UNIQUE = 10; /* Unique symbol.  */
    pub const STB_HIOS = 12; /* End of OS-specific */
    pub const STB_LOPROC = 13; /* Start of processor-specific */
    pub const STB_HIPROC = 15; /* End of processor-specific */
}
pub const STB_LOOS: u8 = 10; /* Start of OS-specific */

/* Symbol visibility specification encoded in the st_other field.  */
const_group_with_fmt! {
    pub struct SymbolVisibility(u8): "STV"

    pub const STV_DEFAULT = 0; /* Default symbol visibility rules */
    pub const STV_INTERNAL = 1; /* Processor specific hidden class */
    pub const STV_HIDDEN = 2; /* Sym unavailable in other modules */
    pub const STV_PROTECTED = 3; /* Not preemptible, not exported */
}

// ------------------
// Relocations
// ------------------

const_group_with_fmt! {
    pub struct RX86_64(u32): "R_X86_64"

    pub const R_X86_64_NONE = 0; /* No reloc */
    pub const R_X86_64_64 = 1; /* Direct 64 bit  */
    pub const R_X86_64_PC32 = 2; /* PC relative 32 bit signed */
    pub const R_X86_64_GOT32 = 3; /* 32 bit GOT entry */
    pub const R_X86_64_PLT32 = 4; /* 32 bit PLT address */
    pub const R_X86_64_COPY = 5; /* Copy symbol at runtime */
    pub const R_X86_64_GLOB_DAT = 6; /* Create GOT entry */
    pub const R_X86_64_JUMP_SLOT = 7; /* Create PLT entry */
    pub const R_X86_64_RELATIVE = 8; /* Adjust by program base */
    pub const R_X86_64_GOTPCREL = 9; /* 32 bit signed PC relative offset to GOT */
    pub const R_X86_64_32 = 10; /* Direct 32 bit zero extended */
    pub const R_X86_64_32S = 11; /* Direct 32 bit sign extended */
    pub const R_X86_64_16 = 12; /* Direct 16 bit zero extended */
    pub const R_X86_64_PC16 = 13; /* 16 bit sign extended pc relative */
    pub const R_X86_64_8 = 14; /* Direct 8 bit sign extended  */
    pub const R_X86_64_PC8 = 15; /* 8 bit sign extended pc relative */
    pub const R_X86_64_DTPMOD64 = 16; /* ID of module containing symbol */
    pub const R_X86_64_DTPOFF64 = 17; /* Offset in module's TLS block */
    pub const R_X86_64_TPOFF64 = 18; /* Offset in initial TLS block */
    pub const R_X86_64_TLSGD = 19; /* 32 bit signed PC relative offset to two GOT entries for GD symbol */
    pub const R_X86_64_TLSLD = 20; /* 32 bit signed PC relative offset to two GOT entries for LD symbol */
    pub const R_X86_64_DTPOFF32 = 21; /* Offset in TLS block */
    pub const R_X86_64_GOTTPOFF = 22; /* 32 bit signed PC relative offset to GOT entry for IE symbol */
    pub const R_X86_64_TPOFF32 = 23; /* Offset in initial TLS block */
    pub const R_X86_64_PC64 = 24; /* PC relative 64 bit */
    pub const R_X86_64_GOTOFF64 = 25; /* 64 bit offset to GOT */
    pub const R_X86_64_GOTPC32 = 26; /* 32 bit signed pc relative offset to GOT */
    pub const R_X86_64_GOT64 = 27; /* 64-bit GOT entry offset */
    pub const R_X86_64_GOTPCREL64 = 28; /* 64-bit PC relative offset to GOT entry */
    pub const R_X86_64_GOTPC64 = 29; /* 64-bit PC relative offset to GOT */
    pub const R_X86_64_GOTPLT64 = 30; /* like GOT64, says PLT entry needed */
    pub const R_X86_64_PLTOFF64 = 31; /* 64-bit GOT relative offset to PLT entry */
    pub const R_X86_64_SIZE32 = 32; /* Size of symbol plus 32-bit addend */
    pub const R_X86_64_SIZE64 = 33; /* Size of symbol plus 64-bit addend */
    pub const R_X86_64_GOTPC32_TLSDESC = 34; /* GOT offset for TLS descriptor.  */
    pub const R_X86_64_TLSDESC_CALL = 35; /* Marker for call through TLS descriptor.  */
    pub const R_X86_64_TLSDESC = 36; /* TLS descriptor.  */
    pub const R_X86_64_IRELATIVE = 37; /* Adjust indirectly by program base */
    pub const R_X86_64_RELATIVE64 = 38; /* 64-bit adjust by program base */
    /* 39 Reserved was R_X86_64_PC32_BND */
    /* 40 Reserved was R_X86_64_PLT32_BND */
    pub const R_X86_64_GOTPCRELX = 41; /* Load from 32 bit signed pc relative offset to GOT entry without REX prefix, relaxable.  */
    pub const R_X86_64_REX_GOTPCRELX = 42; /* Load from 32 bit signed pc relative offset to GOT entry with REX prefix, relaxable.  */
    pub const R_X86_64_NUM = 43;
}

impl SectionIdx {
    pub fn usize(self) -> usize {
        self.0 as usize
    }
}
