use std::path::Path;
use std::convert::TryInto;
use std::io;
use std::fmt;

mod binary_parse;
use binary_parse::Primitive;


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

const PF_X: u8 = 1 << 0;
const PF_W: u8 = 1 << 1;
const PF_R: u8 = 1 << 2;

 pub struct Section {
    pub file_off:       usize,
    pub virt_addr:      usize,
    pub file_size:      usize,
    pub mem_size:       usize,
    pub permissions:    u32,
    pub content:        Vec<u8>
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
 struct Elf64_Ehdr {
     //magic: [u8; 16],
     magic: u32,
     file_class: u8,
     encoding: u8,
     file_version: u8,
     os_abi: u8,
     abi_version: u8,
     padding: [u8; 6],
     ident_size: u8,
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
    std::str::from_utf8(&self.magic.to_le_bytes()[1..]).unwrap(),
    self.file_class,
    self.encoding,
    self.file_version,
    self.os_abi,
    self.abi_version,
    self.ident_size,
    self.e_type,
    self.e_machine,
    self.e_version,
    self.e_entry,
    self.e_phoff,
    self.e_shoff,
    self.e_flags,
    self.e_ehsize,
    self.e_phentsize,
    self.e_phnum,
    self.e_shentsize,
    self.e_shnum,
    self.e_shstrndx
    )}
}

impl Elf64_Ehdr {
    fn new(data: &[u8]) -> Self {
        assert!( (data.len() >=  std::mem::size_of::<Elf64_Ehdr>()) );
        assert_eq!( &data[0..4], [0x7f, 0x45, 0x4c, 0x46], "ELF Magic not found!");
        
        Elf64_Ehdr {
            magic: read_ne_u32(&mut &data[0..4]),
            file_class: data[4],
            encoding: data[5],
            file_version: data[6],
            os_abi: data[7],
            abi_version: data[8],
            padding: [0u8; 6],
            ident_size: data[15],
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

struct elf_module {
    elf_hdr: Elf64_Ehdr,
    //sections: &'t [Section],
}

impl elf_module {

    fn read_file<P: AsRef<Path>>(filename: P) -> io::Result<Vec::<u8>> {
        // read input file
        let contents: Vec<u8> = std::fs::read(filename).ok().expect("unable to read input file");
        Ok(contents)
    }

    pub fn get_loadable_sections<P: AsRef<Path>>(filename: P) -> io::Result<Vec::<Section>> {
        
        let mut contents = elf_module::read_file(filename).unwrap();
        //let header = Elf64_Ehdr::new(&contents[0..64]);
        //println!("{}", &header);
        
        let elf_hdr: &'_ Elf64_Ehdr = binary_parse::from_bytearray(&contents[0..64]).unwrap(); 
        //println!("{}", elf_hdr);
        
        let mut sections = Vec::<Section>::new();

        for idx in 0..elf_hdr.e_phnum {
            let offset = (elf_hdr.e_phoff as usize) + (idx as usize) * core::mem::size_of::<Elf64_Phdr>();           
            let elf_phdr: &'_ Elf64_Phdr = binary_parse::from_bytearray(
                &contents[offset..offset+core::mem::size_of::<Elf64_Phdr>()]).unwrap();

            let pt_type = PtSegmentType::from_u32(elf_phdr.p_type);
            
            match pt_type {
                Some(typ) => {
                    //println!("TYPE: {:?}", typ);
                    match typ {
                        PtSegmentType::PT_LOAD => {                             
                            if (elf_phdr.p_filesz > elf_phdr.p_memsz) {
                                panic!("p_filesz > p_memsz");
                            }
                            if (elf_phdr.p_filesz == 0 ) {
                                panic!("p_filesz = 0");                                
                            }                                         

                            let mut section_content = Vec::<u8>::with_capacity(elf_phdr.p_filesz as usize);
                       
                            section_content.extend_from_slice(
                                contents.get(
                                    elf_phdr.p_offset as usize..elf_phdr.p_offset.checked_add(elf_phdr.p_filesz)
                                    .expect("checked_add failed") as usize)
                                    .expect("contents.get() failed"));

                            sections.push(
                                Section {
                                    file_off: elf_phdr.p_offset as usize,
                                    virt_addr: elf_phdr.p_vaddr as usize,
                                    file_size: elf_phdr.p_filesz as usize,
                                    mem_size: elf_phdr.p_memsz as usize,  
                                    permissions: elf_phdr.p_flags,
                                    content: section_content                        
                            });
                        },
                        _ => {}
                    }
                },
                None => panic!("Unknown segment type")
            }
        }
        
        Ok(sections)
    }
    
    pub fn load_into_vaddr(&self, virtual_addr: u64) -> Option<()> {
        Some(())        
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load() {         
        let sections = elf_module::get_loadable_sections("input_test\\test_app").unwrap();        
        for s in sections {
            println!("{:x}", s.virt_addr);
        }
    }
}