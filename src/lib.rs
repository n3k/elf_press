#![allow(non_camel_case_types)]

use std::path::Path;
use std::convert::TryInto;
use std::io;
use std::fmt;

pub mod binary_parse;
use binary_parse::Primitive;


fn u16_swap(x: u16) -> u16 {
    return (x >> 8) | (x << 8);
}

fn u32_swap(x: u32) -> u32 {
    let byte0 = x >> 0  & 0xff;
    let byte1 = x >> 8  & 0xff;
    let byte2 = x >> 16 & 0xff;
    let byte3 = x >> 24 & 0xff;
    return (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3;
}

fn u64_swap(x: u64) -> u64 {
    let byte0 = x >> 0  & 0xff;
    let byte1 = x >> 8  & 0xff;
    let byte2 = x >> 16 & 0xff;
    let byte3 = x >> 24 & 0xff;
    let byte4 = x >> 32 & 0xff;
    let byte5 = x >> 40 & 0xff;
    let byte6 = x >> 48 & 0xff;
    let byte7 = x >> 56 & 0xff;
    return (byte0 << 56) | (byte1 << 48) | (byte2 << 40) | (byte3 << 32) | (byte4 << 24) | (byte5 << 16) | (byte6 << 8) | byte7;
}

fn read_ne_u8(input: &mut &[u8]) -> u8 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u8>());
    *input = rest;
    u8::from_ne_bytes(int_bytes.try_into().unwrap())
}

fn read_ne_u16(input: &mut &[u8]) -> u16 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u16>());
    *input = rest;
    u16::from_ne_bytes(int_bytes.try_into().unwrap())
}

fn read_ne_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_ne_bytes(int_bytes.try_into().unwrap())
}

fn read_ne_u64(input: &mut &[u8]) -> u64 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
    *input = rest;
    u64::from_ne_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u8(input: &mut &[u8]) -> u8 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u8>());
    *input = rest;
    u8::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u16(input: &mut &[u8]) -> u16 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u16>());
    *input = rest;
    u16::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u64(input: &mut &[u8]) -> u64 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
    *input = rest;
    u64::from_le_bytes(int_bytes.try_into().unwrap())
}

const PF_X: u8 = 1 << 0;
const PF_W: u8 = 1 << 1;
const PF_R: u8 = 1 << 2;

 pub struct Segment {
    pub file_off:       usize,
    pub virt_addr:      usize,
    pub file_size:      usize,
    pub mem_size:       usize,
    pub permissions:    u32,
    pub content:        Vec<u8>
}

impl Segment {
    pub fn size(&self) -> usize {
        if self.file_size < self.mem_size {
            self.mem_size
        } else {
            self.file_size
        }
    }
}

const ELF32_CLASS: u8 = 1;
const ELF64_CLASS: u8 = 2;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum elf_endianess {
    LE = 1,
    BE = 2,
}

impl elf_endianess {
    pub fn from_u8(n: u8) -> Option<elf_endianess> {
        match n {
            1 => Some(elf_endianess::LE),
            2 => Some(elf_endianess::BE),
            _ => None
        }
    }
}

enum elf_file_type {
    ET_NONE = 0,        // No file type
    ET_REL = 1,         // Relocatable file
    ET_EXEC = 2,        // Executable file
    ET_DYN = 3,         // Shared object file
    ET_CORE = 4,        // Core file
    ET_LOPROC = 0xff00, // Beginning of processor-specific codes
    ET_HIPROC = 0xffff  // Processor-specific
 }

 #[derive(Default, Copy, Clone)]
 #[repr(packed, C)]
 struct ElfIdent {
     magic: u32,
     file_class: u8,
     encoding: u8,
     file_version: u8,
     os_abi: u8,
     abi_version: u8,
     padding: [u8; 6],
     ident_size: u8
 }

 impl ElfIdent {

    fn is_le(&self) -> bool {        
        return elf_endianess::from_u8(self.encoding).unwrap() == elf_endianess::LE;
    }

    fn is_be(&self) -> bool {
        return elf_endianess::from_u8(self.encoding).unwrap() == elf_endianess::BE;
    }
    
    fn is_32(&self) -> bool {
        return self.file_class == ELF32_CLASS;
    }

    fn is_64(&self) -> bool {
        return self.file_class == ELF64_CLASS;
    }
 }

 impl From<&[u8]> for ElfIdent {
    fn from(bytes: &[u8]) -> Self {
        ElfIdent {
            magic: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            file_class: bytes[4],
            encoding: bytes[5],
            file_version: bytes[6],
            os_abi: bytes[7],
            abi_version: bytes[8],
            padding: [0u8; 6],
            ident_size: bytes[15],       
        }
    }
 }

 unsafe impl Primitive for ElfIdent {}
 
 #[derive(Default, Copy, Clone)]
 #[repr(packed, C)]
 struct Elf64_Ehdr {
     //magic: [u8; 16],
     ident: ElfIdent,
     e_type: u16,        // Type of file
     e_machine: u16,     // Required architecture for this file
     e_version: u32,     // Must be equal to 1
     e_entry: u64,       // Address to jump to in order to start program
     e_phoff: u64,       // Program header table's file offset, in bytes
     e_shoff: u64,       // Section header table's file offset, in bytes
     e_flags: u32,       // Processor-specific flags
     e_ehsize: u16,      // Size of ELF header, in bytes
     e_phentsize: u16,   // Size of an entry in the program header table
     e_phnum: u16,       // Number of entries in the program header table
     e_shentsize: u16,   // Size of an entry in the section header table
     e_shnum: u16,       // Number of entries in the section header table
     e_shstrndx: u16,    // Sect hdr table index of sect name string table
 }

 unsafe impl Primitive for Elf64_Ehdr {}

 #[derive(Default, Copy, Clone)]
 #[repr(packed, C)]
 struct Elf32_Ehdr {
     //magic: [u8; 16],
     ident: ElfIdent,
     e_type: u16,        // Type of file
     e_machine: u16,     // Required architecture for this file
     e_version: u32,     // Must be equal to 1
     e_entry: u32,       // Address to jump to in order to start program
     e_phoff: u32,       // Program header table's file offset, in bytes
     e_shoff: u32,       // Section header table's file offset, in bytes
     e_flags: u32,       // Processor-specific flags
     e_ehsize: u16,      // Size of ELF header, in bytes
     e_phentsize: u16,   // Size of an entry in the program header table
     e_phnum: u16,       // Number of entries in the program header table
     e_shentsize: u16,   // Size of an entry in the section header table
     e_shnum: u16,       // Number of entries in the section header table
     e_shstrndx: u16,    // Sect hdr table index of sect name string table
 }

 unsafe impl Primitive for Elf32_Ehdr {}




 impl fmt::Display for Elf64_Ehdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"( 
  -> magic: {}
  -> file_class: {}
  -> encoding: {}
  -> file_version: {}
  -> os_abi: {}
  -> abi_version: {}
  -> ident_size: {},
  -> e_type: {},
  -> e_machine: {},
  -> e_version: {},
  -> e_entry: {:#x},
  -> e_phoff: {:#x},
  -> e_shoff: {:#x},
  -> e_flags: {},
  -> e_ehsize: {:#x},
  -> e_phentsize: {:#x},
  -> e_phnum: {},
  -> e_shentsize: {:#x},
  -> e_shnum: {},
  -> e_shstrndx: {},
)"#,
    std::str::from_utf8(&self.ident.magic.to_le_bytes()[1..]).unwrap(),
    self.ident.file_class,
    self.ident.encoding,
    self.ident.file_version,
    self.ident.os_abi,
    self.ident.abi_version,
    self.ident.ident_size,
    {self.e_type},
    {self.e_machine},
    {self.e_version},
    {self.e_entry},
    {self.e_phoff},
    {self.e_shoff},
    {self.e_flags},
    {self.e_ehsize},
    {self.e_phentsize},
    {self.e_phnum},
    {self.e_shentsize},
    {self.e_shnum},
    {self.e_shstrndx}
    )}
}


impl fmt::Display for Elf32_Ehdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"( 
  -> magic: {}
  -> file_class: {}
  -> encoding: {}
  -> file_version: {}
  -> os_abi: {}
  -> abi_version: {}
  -> ident_size: {},
  -> e_type: {},
  -> e_machine: {},
  -> e_version: {},
  -> e_entry: {:#x},
  -> e_phoff: {:#x},
  -> e_shoff: {:#x},
  -> e_flags: {},
  -> e_ehsize: {:#x},
  -> e_phentsize: {:#x},
  -> e_phnum: {},
  -> e_shentsize: {:#x},
  -> e_shnum: {},
  -> e_shstrndx: {},
)"#,
    std::str::from_utf8(&self.ident.magic.to_le_bytes()[1..]).unwrap(),
    self.ident.file_class,
    self.ident.encoding,
    self.ident.file_version,
    self.ident.os_abi,
    self.ident.abi_version,
    self.ident.ident_size,
    {self.e_type},
    {self.e_machine},
    {self.e_version},
    {self.e_entry},
    {self.e_phoff},
    {self.e_shoff},
    {self.e_flags},
    {self.e_ehsize},
    {self.e_phentsize},
    {self.e_phnum},
    {self.e_shentsize},
    {self.e_shnum},
    {self.e_shstrndx}
    )}
}

impl Elf64_Ehdr {
    fn new(data: &[u8]) -> Self {
        assert!( (data.len() >=  std::mem::size_of::<Elf64_Ehdr>()) );
        assert_eq!( &data[0..5], [0x7f, 0x45, 0x4c, 0x46, 0x02], "ELF64 Magic not found!");
        
        let ident = ElfIdent::from(data);

        if ident.is_le() {
            Elf64_Ehdr {
                ident: ident,
                e_type: read_le_u16(&mut &data[16..18]),
                e_machine: read_le_u16(&mut &data[18..20]),
                e_version: read_le_u32(&mut &data[20..24]),
                e_entry: read_le_u64(&mut &data[24..32]),
                e_phoff: read_le_u64(&mut &data[32..40]),
                e_shoff: read_le_u64(&mut &data[40..48]),
                e_flags: read_le_u32(&mut &data[48..52]),
                e_ehsize:  read_le_u16(&mut &data[52..54]),
                e_phentsize: read_le_u16(&mut &data[54..56]),
                e_phnum: read_le_u16(&mut &data[56..58]),
                e_shentsize: read_le_u16(&mut &data[58..60]),
                e_shnum: read_le_u16(&mut &data[60..62]),
                e_shstrndx: read_le_u16(&mut &data[62..64]),
            }
        } else {
            Elf64_Ehdr {
                ident: ident,
                e_type: read_ne_u16(&mut &data[16..18]),
                e_machine: read_ne_u16(&mut &data[18..20]),
                e_version: read_ne_u32(&mut &data[20..24]),
                e_entry: read_ne_u64(&mut &data[24..32]),
                e_phoff: read_ne_u64(&mut &data[32..40]),
                e_shoff: read_ne_u64(&mut &data[40..48]),
                e_flags: read_ne_u32(&mut &data[48..52]),
                e_ehsize:  read_ne_u16(&mut &data[52..54]),
                e_phentsize: read_ne_u16(&mut &data[54..56]),
                e_phnum: read_ne_u16(&mut &data[56..58]),
                e_shentsize: read_ne_u16(&mut &data[58..60]),
                e_shnum: read_ne_u16(&mut &data[60..62]),
                e_shstrndx: read_ne_u16(&mut &data[62..64]),
            }
        }
        
    }
}

impl Elf32_Ehdr {
    fn new(data: &[u8]) -> Self {
        assert!( (data.len() >=  std::mem::size_of::<Elf32_Ehdr>()) );
        assert_eq!( &data[0..5], [0x7f, 0x45, 0x4c, 0x46, 0x01], "ELF32 Magic not found!");
        
        let ident = ElfIdent::from(data);

        if ident.is_le() {
            Elf32_Ehdr {
                ident: ident,
                e_type: read_le_u16(&mut &data[16..18]),
                e_machine: read_le_u16(&mut &data[18..20]),
                e_version: read_le_u32(&mut &data[20..24]),
                e_entry: read_le_u32(&mut &data[24..28]),
                e_phoff: read_le_u32(&mut &data[28..32]),
                e_shoff: read_le_u32(&mut &data[32..36]),
                e_flags: read_le_u32(&mut &data[36..40]),
                e_ehsize:  read_le_u16(&mut &data[40..42]),
                e_phentsize: read_le_u16(&mut &data[42..44]),
                e_phnum: read_le_u16(&mut &data[44..46]),
                e_shentsize: read_le_u16(&mut &data[46..48]),
                e_shnum: read_le_u16(&mut &data[48..50]),
                e_shstrndx: read_le_u16(&mut &data[50..52]),
            }
        } else {
            Elf32_Ehdr {
                ident: ident,
                e_type: read_ne_u16(&mut &data[16..18]),
                e_machine: read_ne_u16(&mut &data[18..20]),
                e_version: read_ne_u32(&mut &data[20..24]),
                e_entry: read_ne_u32(&mut &data[24..28]),
                e_phoff: read_ne_u32(&mut &data[28..32]),
                e_shoff: read_ne_u32(&mut &data[32..36]),
                e_flags: read_ne_u32(&mut &data[36..40]),
                e_ehsize:  read_ne_u16(&mut &data[40..42]),
                e_phentsize: read_ne_u16(&mut &data[42..44]),
                e_phnum: read_ne_u16(&mut &data[44..46]),
                e_shentsize: read_ne_u16(&mut &data[46..48]),
                e_shnum: read_ne_u16(&mut &data[48..50]),
                e_shstrndx: read_ne_u16(&mut &data[50..52]),
            }
        }
        
    }
}

 // Segment types.
 #[derive(Debug)]
 enum PtSegmentType{
    PT_NULL = 0,            // Unused segment.
    PT_LOAD = 1,            // Loadable segment.
    PT_DYNAMIC = 2,         // Dynamic linking information.
    PT_INTERP = 3,          // Interpreter pathname.
    PT_NOTE = 4,            // Auxiliary information.
    PT_SHLIB = 5,           // Reserved.
    PT_PHDR = 6,            // The program header table itself.
    PT_TLS = 7,             // The thread-local storage template.
    PT_LOOS = 0x60000000,   // Lowest operating system-specific pt entry type.
    PT_HIOS = 0x6fffffff,   // Highest operating system-specific pt entry type.
    PT_LOPROC = 0x70000000, // Lowest processor-specific program hdr entry type.
    PT_HIPROC = 0x7fffffff, // Highest processor-specific program hdr entry type.
  
    // x86-64 program header types.
    // These all contain stack unwind tables.
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_SUNW_UNWIND = 0x6464e550,
  
    PT_GNU_STACK = 0x6474e551, // Indicates stack executability.
    PT_GNU_RELRO = 0x6474e552, // Read-only after relocation.
  
    PT_OPENBSD_RANDOMIZE = 0x65a3dbe6, // Fill with random data.
    PT_OPENBSD_WXNEEDED = 0x65a3dbe7,  // Program does W^X violations.
    PT_OPENBSD_BOOTDATA = 0x65a41be6,  // Section for boot arguments.
    PT_ARM_EXIDX        = 0x70000001, 
  }

impl PtSegmentType {
    pub fn from_u32(n: u32) -> Option<PtSegmentType> {
        match n {
            0 => Some(PtSegmentType::PT_NULL),
            1 => Some(PtSegmentType::PT_LOAD),
            2 => Some(PtSegmentType::PT_DYNAMIC),
            3 => Some(PtSegmentType::PT_INTERP),
            4 => Some(PtSegmentType::PT_NOTE),
            5 => Some(PtSegmentType::PT_SHLIB),
            6 => Some(PtSegmentType::PT_PHDR),
            7 => Some(PtSegmentType::PT_TLS),
            0x60000000 => Some(PtSegmentType::PT_LOOS),
            0x6fffffff => Some(PtSegmentType::PT_HIOS),
            0x70000000 => Some(PtSegmentType::PT_LOPROC),
            0x7fffffff => Some(PtSegmentType::PT_HIPROC),
            0x6474e550 => Some(PtSegmentType::PT_GNU_EH_FRAME),
            0x6464e550 => Some(PtSegmentType::PT_SUNW_UNWIND),
            0x6474e551 => Some(PtSegmentType::PT_GNU_STACK),
            0x6474e552 => Some(PtSegmentType::PT_GNU_RELRO),
            0x65a3dbe6 => Some(PtSegmentType::PT_OPENBSD_RANDOMIZE),
            0x65a3dbe7 => Some(PtSegmentType::PT_OPENBSD_WXNEEDED),
            0x65a41be6 => Some(PtSegmentType::PT_OPENBSD_BOOTDATA),
            0x70000001 => Some(PtSegmentType::PT_ARM_EXIDX),
            _ => None
        }
    }
}




/// Program header for ELF64.
#[derive(Default, Copy, Clone)]
#[repr(packed, C)]
struct Elf64_Phdr {
    p_type: u32,    // Type of segment
    p_flags: u32,   // Segment flags
    p_offset: u64,   // File offset where segment is located, in bytes
    p_vaddr: u64,   // Virtual address of beginning of segment
    p_paddr: u64,   // Physical addr of beginning of segment (OS-specific)
    p_filesz: u64, // Num. of bytes in file image of segment (may be zero)
    p_memsz: u64,  // Num. of bytes in mem image of segment (may be zero)
    p_align: u64,  // Segment alignment constraint
}

unsafe impl Primitive for Elf64_Phdr {}


/// Program header for ELF32.
#[derive(Default, Copy, Clone)]
#[repr(packed, C)]
struct Elf32_Phdr {
    p_type: u32,    // Type of segment    
    p_offset: u32,   // File offset where segment is located, in bytes
    p_vaddr: u32,   // Virtual address of beginning of segment
    p_paddr: u32,   // Physical addr of beginning of segment (OS-specific)
    p_filesz: u32, // Num. of bytes in file image of segment (may be zero)
    p_memsz: u32,  // Num. of bytes in mem image of segment (may be zero)
    p_flags: u32,   // Segment flags
    p_align: u32,  // Segment alignment constraint
}

unsafe impl Primitive for Elf32_Phdr {}

impl fmt::Display for Elf32_Phdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"( 
  -> p_type: {:#08x}  
  -> p_offset: {:#08x}
  -> p_vaddr: {:#08x}
  -> p_paddr: {:#08x}
  -> p_filesz: {:#08x}
  -> p_memsz: {:#08x}
  -> p_flags: {:#08x}
  -> p_align: {:#08x}
)"#,
    {self.p_type},    
    {self.p_offset},
    {self.p_vaddr},
    {self.p_paddr},
    {self.p_filesz},
    {self.p_memsz},
    {self.p_flags},
    {self.p_align}
    )}
}


/// Section Header Types
#[derive(Debug)]
enum SHType {
    NULL = 0,           // No associated section (inactive entry).
    PROGBITS = 1,       // Program-defined contents.
    SYMTAB = 2,         // Symbol table.
    STRTAB = 3,         // String table.
    RELA = 4,           // Relocation entries; explicit addends.
    HASH = 5,           // Symbol hash table.
    DYNAMIC = 6,        // Information for dynamic linking.
    NOTE = 7,           // Information about the file.
    NOBITS = 8,         // Data occupies no space in the file.
    REL = 9,            // Relocation entries; no explicit addends.
    SHLIB = 10,         // Reserved.
    DYNSYM = 11,        // Symbol table.
    INIT_ARRAY = 14,    // Pointers to initialization functions.
    FINI_ARRAY = 15,    // Pointers to termination functions.
    PREINIT_ARRAY = 16, // Pointers to pre-init functions.
    GROUP = 17,         // Section group.
    SYMTAB_SHNDX = 18,  // Indices for SHN_XINDEX entries.
}

impl SHType {
    pub fn from_u32(n: u32) -> Option<SHType> {
        match n {
            0  => Some(SHType::NULL),
            1  => Some(SHType::PROGBITS),
            2  => Some(SHType::SYMTAB),
            3  => Some(SHType::STRTAB),
            4  => Some(SHType::RELA),
            5  => Some(SHType::HASH),
            6  => Some(SHType::DYNAMIC),
            7  => Some(SHType::NOTE),
            8  => Some(SHType::NOBITS),
            9  => Some(SHType::REL),
            10 => Some(SHType::SHLIB),
            11 => Some(SHType::DYNSYM),
            14 => Some(SHType::INIT_ARRAY),
            15 => Some(SHType::FINI_ARRAY),
            16 => Some(SHType::PREINIT_ARRAY),
            17 => Some(SHType::GROUP),
            18 => Some(SHType::SYMTAB_SHNDX),
            _ => None
        }
    }
}

 /// Section header for ELF64 - same fields as ELF32, different types.
 #[derive(Default, Copy, Clone)]
 #[repr(packed, C)]
 struct Elf64_Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

unsafe impl Primitive for Elf64_Shdr {}


#[derive(Default, Copy, Clone)]
#[repr(packed, C)]
struct Elf32_Shdr {
   sh_name: u32,
   sh_type: u32,
   sh_flags: u32,
   sh_addr: u32,
   sh_offset: u32,
   sh_size: u32,
   sh_link: u32,
   sh_info: u32,
   sh_addralign: u32,
   sh_entsize: u32,
}

impl fmt::Display for Elf32_Shdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"( 
  -> sh_name: {:#08x}  
  -> sh_type: {:#08x}
  -> sh_flags: {:#08x}
  -> sh_addr: {:#08x}
  -> sh_offset: {:#08x}
  -> sh_size: {:#08x}
  -> sh_link: {:#08x}
  -> sh_info: {:#08x}
  -> sh_addralign: {:#08x}
  -> sh_entsize: {:#08x}
)"#,
    {self.sh_name},    
    {self.sh_type},
    {self.sh_flags},
    {self.sh_addr},
    {self.sh_offset},
    {self.sh_size},
    {self.sh_link},
    {self.sh_info},
    {self.sh_addralign},
    {self.sh_entsize},
    )}
}

unsafe impl Primitive for Elf32_Shdr {}


/// Symbol table entries for ELF64.
#[derive(Default, Copy, Clone)]
#[repr(packed, C)]
struct Elf64_Sym {
    st_name: u32,       // Symbol name (index into string table)
    st_info: u8,        // Symbol's type and binding attributes
    st_other: u8,       // Must be zero; reserved
    st_shndx: u16,      // Which section (header tbl index) it's defined in
    st_value: u64,      // Value or address associated with the symbol
    st_size: u64        // Size of the symbol
}

unsafe impl Primitive for Elf64_Sym {}


/// Symbol bindings.
#[derive(Copy, Clone, PartialEq, PartialOrd, Ord, Eq)]
enum STB {
    LOCAL = 0,  // Local symbol, not visible outside obj file containing def
    GLOBAL = 1, // Global symbol, visible to all object files being combined
    WEAK = 2,   // Weak symbol, like global but lower-precedence    
    LOOS = 10,   // Lowest operating system-specific binding type
    HIOS = 12,   // Highest operating system-specific binding type
    LOPROC = 13, // Lowest processor-specific binding type
    HIPROC = 15,  // Highest processor-specific binding type

    UNDEFINED
}

impl STB {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => STB::LOCAL,
            1 => STB::GLOBAL,
            2 => STB::WEAK,
            10 => STB::LOOS,            
            12 => STB::HIOS,
            13 => STB::LOPROC,
            15 => STB::HIPROC,
            _  => STB::UNDEFINED
        }
    }
}
   
/// Symbol types.
#[derive(Copy, Clone, PartialEq, PartialOrd, Ord, Eq)]
enum STT {
    NOTYPE = 0,     // Symbol's type is not specified
    OBJECT = 1,     // Symbol is a data object (variable, array, etc.)
    FUNC = 2,       // Symbol is executable code (function, etc.)
    SECTION = 3,    // Symbol refers to a section
    FILE = 4,       // Local, absolute symbol that refers to a file
    COMMON = 5,     // An uninitialized common block
    TLS = 6,        // Thread local data object
    GNU_IFUNC = 10, // GNU indirect function
    HIOS = 12,      // Highest operating system-specific symbol type
    LOPROC = 13,    // Lowest processor-specific symbol type
    HIPROC = 15,    // Highest processor-specific symbol type

    UNDEFINED
}

impl STT {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => STT::NOTYPE,
            1 => STT::OBJECT,
            2 => STT::FUNC,
            3 => STT::SECTION,
            4 => STT::FILE,
            5 => STT::COMMON,
            6 => STT::TLS,
            10 => STT::GNU_IFUNC,
            12 => STT::HIOS,
            13 => STT::LOPROC,
            15 => STT::HIPROC,
            _  => STT::UNDEFINED
        }
    }
}

/// Symbol table entries for ELF32.
#[derive(Default, Copy, Clone)]
#[repr(packed, C)]
struct Elf32_Sym {
    st_name: u32,     // Symbol name (index into string table)
    st_value: u32,    // Value or address associated with the symbol
    st_size: u32,     // Size of the symbol
    st_info: u8,      // Symbol's type and binding attributes
    st_other: u8,     // Must be zero; reserved
    st_shndx: u16     // Which section (header table index) it's defined in
}

impl Elf32_Sym {

    fn get_binding(&self) -> STB {
        STB::from_u8(self.st_info >> 4)
    }

    fn get_type(&self) -> STT {
        STT::from_u8(self.st_info & 0x0F)
    }
}

impl fmt::Display for Elf32_Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"( 
  -> st_name: {:#08x}  
  -> st_value: {:#08x}
  -> st_size: {:#08x}
)"#,
    {self.st_name},    
    {self.st_value},
    {self.st_size},
    )}
}

unsafe impl Primitive for Elf32_Sym {}


pub struct elf_module {
    // is ELF64
    pub is_elf64: bool,
    pub endianess:  elf_endianess,

    /// Entry point of the program
    pub entry_point: u64,

    /// A list of loadable segments
    pub segments: Vec::<Segment>,

    /// A vector of (name, value, size, Option<SymbolNameString>)
    /// This only represents the GLOBAL FUNC Symbols of the ELF
    pub global_symbols: Vec::<(u32, u32, u32, Option<String>)>
}

impl elf_module {

    fn read_file<P: AsRef<Path>>(filename: P) -> io::Result<Vec::<u8>> {
        // read input file
        let contents: Vec<u8> = std::fs::read(filename).ok().expect("unable to read input file");
        Ok(contents)
    }

    /// Retrieves the lodable segments of the ELF32
    /// It also sets the entry point
    fn get_loadable_segments_32(contents: &[u8], 
        endianess: elf_endianess, entry_point: &mut u64) -> Vec<Segment> 
    {
        let mut segments = Vec::<Segment>::new();

        let elf_hdr: &'_ Elf32_Ehdr = binary_parse::from_bytearray(&contents[0..64]).unwrap();
            *entry_point = elf_hdr.e_entry as u64;

        for idx in 0..elf_hdr.e_phnum {
            let offset = (elf_hdr.e_phoff as usize) + (idx as usize) * core::mem::size_of::<Elf32_Phdr>();  
            //println!("Offset of Elf32_Phdr: {:#08x}", offset);         
            let elf_phdr: &'_ Elf32_Phdr = binary_parse::from_bytearray(
                &contents[offset..offset+core::mem::size_of::<Elf32_Phdr>()]).unwrap();
            
            //println!("{}", elf_phdr);
            let mut p_type = elf_phdr.p_type;  
            let mut p_filesz = elf_phdr.p_filesz;
            let mut p_memsz = elf_phdr.p_memsz;
            let mut p_offset = elf_phdr.p_offset;
            let mut p_vaddr = elf_phdr.p_vaddr;
            let mut p_flags = elf_phdr.p_flags;

            if elf_endianess::BE == endianess {
                *entry_point = u32_swap(*entry_point as u32) as u64;
                p_type   = u32_swap(p_type);
                p_filesz = u32_swap(p_filesz);
                p_memsz  = u32_swap(p_memsz);
                p_offset = u32_swap(p_offset);
                p_vaddr  = u32_swap(p_vaddr);
                p_flags  = u32_swap(p_flags);
            }
                
            let pt_type = PtSegmentType::from_u32(p_type);
            
            //println!("PHeader: {}", elf_phdr);
            match pt_type {
                Some(typ) => {
                    //println!("TYPE: {:?}", typ);
                    match typ {
                        PtSegmentType::PT_LOAD => {                             
                            // if elf_phdr.p_filesz > elf_phdr.p_memsz {
                            //     panic!("p_filesz > p_memsz");
                            // }
                            if elf_phdr.p_filesz == 0 {
                                panic!("p_filesz = 0");                                
                            }                                         

                            let mut segment_content = Vec::<u8>::with_capacity(p_filesz as usize);
                            
                            segment_content.extend_from_slice(
                                contents.get(
                                    p_offset as usize..p_offset.checked_add(p_filesz)
                                    .expect("checked_add failed") as usize)
                                    .expect("contents.get() failed"));

                            segments.push(
                                Segment {
                                    file_off: p_offset as usize,
                                    virt_addr: p_vaddr as usize,
                                    file_size: p_filesz as usize,
                                    mem_size: p_memsz as usize,  
                                    permissions: p_flags,
                                    content: segment_content                        
                            });
                        },
                        _ => {}
                    }
                },
                None => panic!("Unknown segment type: {}", {elf_phdr.p_type})
            }
        }

        return segments;
    }

    /// Returns a list with the GLOBAL symbols of the ELF32
    fn get_symbols_32(contents: &[u8], endianess: elf_endianess) -> Vec<(u32, u32, u32, Option<String>)> {

        let elf_hdr: &'_ Elf32_Ehdr = binary_parse::from_bytearray(&contents[0..64]).unwrap();

        let mut symbol_data_array = Vec::<(u32, u32, u32, Option<String>)>::new();

        // Walk the section header to find the Symbols and collect information
        for idx in 0..elf_hdr.e_shnum {
            let offset = (elf_hdr.e_shoff as usize) + (idx as usize) * core::mem::size_of::<Elf32_Shdr>();
            let elf_shdr: &'_ Elf32_Shdr = binary_parse::from_bytearray(
                &contents[offset..offset+core::mem::size_of::<Elf32_Shdr>()]).unwrap();
            
            if endianess == elf_endianess::BE {
                unimplemented!("implement BE transformations!");
            }

            match SHType::from_u32(elf_shdr.sh_type) {
                Some(SHType::SYMTAB) => {                      
                    let num_symbols =  elf_shdr.sh_size as usize / core::mem::size_of::<Elf32_Sym>();
                    for i in 0..num_symbols {
                        let offset = (elf_shdr.sh_offset as usize) + i * core::mem::size_of::<Elf32_Sym>();   
                        let elf_sym: &'_ Elf32_Sym = binary_parse::from_bytearray(
                            &contents[offset..offset+core::mem::size_of::<Elf32_Sym>()]).unwrap();  
                        
                        if elf_sym.get_binding() == STB::GLOBAL && elf_sym.get_type() == STT::FUNC {
                            symbol_data_array.push(
                                (elf_sym.st_name, elf_sym.st_value, elf_sym.st_size, None)
                            );                        
                        }                        
                    }
                    break;
                }
                _ => {}
            }
        }

        // Walk the section headers again to complete the symbol name with the STRTAB
        for idx in 0..elf_hdr.e_shnum {
            let offset = (elf_hdr.e_shoff as usize) + (idx as usize) * core::mem::size_of::<Elf32_Shdr>();
            let elf_shdr: &'_ Elf32_Shdr = binary_parse::from_bytearray(
                &contents[offset..offset+core::mem::size_of::<Elf32_Shdr>()]).unwrap();
            
            if endianess == elf_endianess::BE {
                unimplemented!("implement BE transformations!");
            }

            match SHType::from_u32(elf_shdr.sh_type) {
                Some(SHType::STRTAB) => {                          
                    let string_table_base = elf_shdr.sh_offset as usize;                    
                    for i in 0..symbol_data_array.len() {                        
                        let (name, _value, _size, op_name) 
                            = &mut symbol_data_array[i];

                        // println!("{:#08x} {:#08x} {:#08x} --> {:#08x}",
                        //       *name, *_value, *_size, *name as usize + string_table_base);
                        
                        // offset into the string table for the current symbol name
                        let offset = string_table_base + *name as usize;

                        // Determine length of the C string
                        let mut str_len = 0;
                        while contents[offset + str_len] != 0 {
                            str_len += 1;
                        }

                        // Try Get the UTF-8 version
                        if let Ok(str_name) = std::str::from_utf8(&contents[offset..(offset+str_len)]) {
                            //println!("{}", &str_name);
                            // Set the Option 
                            *op_name = Some(str_name.into());
                        }                          
                    }
                    break;
                }
                _ => {}
            }
        }

        return symbol_data_array;
    }

    /// Retrieves the lodable Segments of the ELF64
    /// It also sets the entry point
    fn get_loadable_segments_64(contents: &[u8], 
        endianess: elf_endianess, entry_point: &mut u64) -> Vec<Segment> 
    {
        let mut segments = Vec::<Segment>::new();

        let elf_hdr: &'_ Elf64_Ehdr = binary_parse::from_bytearray(&contents[0..64]).unwrap();
        *entry_point = elf_hdr.e_entry;

        for idx in 0..elf_hdr.e_phnum {
            let offset = (elf_hdr.e_phoff as usize) + (idx as usize) * core::mem::size_of::<Elf64_Phdr>();           
            let elf_phdr: &'_ Elf64_Phdr = binary_parse::from_bytearray(
                &contents[offset..offset+core::mem::size_of::<Elf64_Phdr>()]).unwrap();

            let mut p_type = elf_phdr.p_type;  
            let mut p_filesz = elf_phdr.p_filesz;
            let mut p_memsz = elf_phdr.p_memsz;
            let mut p_offset = elf_phdr.p_offset;
            let mut p_vaddr = elf_phdr.p_vaddr;
            let mut p_flags = elf_phdr.p_flags;

            if elf_endianess::BE == endianess {
                *entry_point = u64_swap(*entry_point);
                p_type   = u32_swap(p_type);
                p_filesz = u64_swap(p_filesz);
                p_memsz  = u64_swap(p_memsz);
                p_offset = u64_swap(p_offset);
                p_vaddr  = u64_swap(p_vaddr);
                p_flags  = u32_swap(p_flags);
            }
                
            let pt_type = PtSegmentType::from_u32(p_type);
            
            match pt_type {
                Some(typ) => {
                    //println!("TYPE: {:?}", typ);
                    match typ {
                        PtSegmentType::PT_LOAD => {                             
                            if p_filesz > p_memsz {
                                panic!("p_filesz > p_memsz");
                            }
                            if p_filesz == 0 {
                                panic!("p_filesz = 0");                                
                            }                                         

                            let mut segment_content = Vec::<u8>::with_capacity(p_filesz as usize);
                        
                            segment_content.extend_from_slice(
                                contents.get(
                                    p_offset as usize..p_offset.checked_add(p_filesz)
                                    .expect("checked_add failed") as usize)
                                    .expect("contents.get() failed"));

                            segments.push(
                                Segment {
                                    file_off: p_offset as usize,
                                    virt_addr: p_vaddr as usize,
                                    file_size: p_filesz as usize,
                                    mem_size: p_memsz as usize,  
                                    permissions: p_flags,
                                    content: segment_content                        
                            });
                        },
                        _ => {}
                    }
                },
                None => panic!("Unknown segment type")
            }
        }

        return segments;
    }

    
    /// Returns a list with the GLOBAL symbols of the ELF64
    fn get_symbols_64(contents: &[u8], endianess: elf_endianess) -> Vec<(u32, u32, u32, Option<String>)> {
        unimplemented!("Implement get_symbols_64")
    }


    pub fn new<P: AsRef<Path>>(filename: P) -> io::Result<elf_module> {
        
        let contents = elf_module::read_file(filename).unwrap();
        
        let elf_ident: &'_ ElfIdent = binary_parse::from_bytearray(&contents[0..16]).unwrap(); 
        
        let segments: Vec::<Segment>;
        let global_symbols: Vec::<(u32, u32, u32, Option<String>)>;

        let mut is_elf64 = false;
        let mut entry_point: u64 = 0;
        let endianess = elf_endianess::from_u8(elf_ident.encoding).unwrap();

        match elf_ident.file_class {
            ELF32_CLASS => {
                segments       = elf_module::get_loadable_segments_32(&contents, endianess, &mut entry_point);
                global_symbols = elf_module::get_symbols_32(&contents, endianess);
            },
            ELF64_CLASS => {
                segments = elf_module::get_loadable_segments_64(&contents, endianess, &mut entry_point);
                is_elf64 = true;
                global_symbols = elf_module::get_symbols_64(&contents, endianess);
            },
            _ => panic!("Invalid ELF Class")
        };

        Ok(elf_module {
            is_elf64: is_elf64,
            endianess: endianess,
            entry_point: entry_point,
            segments: segments,
            global_symbols: global_symbols
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_elf32_arm_newlib() {         
        let elf = elf_module::new("/home/n3k/Documents/Projects/bicep/test").unwrap();        
        for s in elf.segments {
            println!("{:x} - {:x}", s.virt_addr, s.size());
        }
    }
}
