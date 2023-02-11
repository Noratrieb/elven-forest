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
                    a => write!(f, "Invalid {}: {a}", $group_name,)
                }
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
pub const ELFCLASSNONE: u8 = 0; /* Invalid class */
pub const ELFCLASS32: u8 = 1; /* 32-bit objects */
pub const ELFCLASS64: u8 = 2; /* 64-bit objects */
pub const ELFCLASSNUM: u8 = 3;

pub const EI_DATA: usize = 5; /* Data encoding byte index */
pub const ELFDATANONE: u8 = 0; /* Invalid data encoding */
pub const ELFDATA2LSB: u8 = 1; /* 2's complement, little endian */
pub const ELFDATA2MSB: u8 = 2; /* 2's complement, big endian */
pub const ELFDATANUM: u8 = 3;

pub const EI_VERSION: usize = 6; /* File version byte index */

pub const EI_OSABI: usize = 7; /* OS ABI identification */
pub const ELFOSABI_NONE: u8 = 0; /* UNIX System V ABI */
pub const ELFOSABI_SYSV: u8 = 0; /* Alias.  */
pub const ELFOSABI_HPUX: u8 = 1; /* HP-UX */
pub const ELFOSABI_NETBSD: u8 = 2; /* NetBSD.  */
pub const ELFOSABI_GNU: u8 = 3; /* Object uses GNU ELF extensions.  */
pub const ELFOSABI_LINUX: u8 = ELFOSABI_GNU; /* Compatibility alias.  */
pub const ELFOSABI_SOLARIS: u8 = 6; /* Sun Solaris.  */
pub const ELFOSABI_AIX: u8 = 7; /* IBM AIX.  */
pub const ELFOSABI_IRIX: u8 = 8; /* SGI Irix.  */
pub const ELFOSABI_FREEBSD: u8 = 9; /* FreeBSD.  */
pub const ELFOSABI_TRU64: u8 = 10; /* Compaq TRU64 UNIX.  */
pub const ELFOSABI_MODESTO: u8 = 11; /* Novell Modesto.  */
pub const ELFOSABI_OPENBSD: u8 = 12; /* OpenBSD.  */
pub const ELFOSABI_ARM_AEABI: u8 = 64; /* ARM EABI */
pub const ELFOSABI_ARM: u8 = 97; /* ARM */
pub const ELFOSABI_STANDALONE: u8 = 255; /* Standalone (embedded) application */

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

pub const SHN_UNDEF: u16 = 0; /* Undefined section */
pub const SHN_LORESERVE: u16 = 0xff00; /* Start of reserved indices */
pub const SHN_LOPROC: u16 = 0xff00; /* Start of processor-specific */
pub const SHN_BEFORE: u16 = 0xff00; /* Order section before all others (Solaris).  */
pub const SHN_AFTER: u16 = 0xff01; /* Order section after all others (Solaris).  */
pub const SHN_HIPROC: u16 = 0xff1f; /* End of processor-specific */
pub const SHN_LOOS: u16 = 0xff20; /* Start of OS-specific */
pub const SHN_HIOS: u16 = 0xff3f; /* End of OS-specific */
pub const SHN_ABS: u16 = 0xfff1; /* Associated symbol is absolute */
pub const SHN_COMMON: u16 = 0xfff2; /* Associated symbol is common */
pub const SHN_XINDEX: u16 = 0xffff; /* Index is in extra table.  */
pub const SHN_HIRESERVE: u16 = 0xffff; /* End of reserved indices */

const_group_with_fmt! {
    pub struct ShType(u32): "Section header type"

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
