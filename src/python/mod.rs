pub mod disasm;
pub mod disassembler;
pub mod nuitka_mod;
pub mod pseudo_cc;
pub mod pyc_parser;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct TOCEntry {
    pub name: String,
    pub dpos: u32,
    pub dlen: u32,
    pub ulen: u32,
    pub cmpr: u8,
    pub type_cmpr: u8,
}

#[allow(dead_code)]
pub struct PyInstallerArchive {
    pub magic_offset: u64,
    pub pkg_length: u64,
    pub toc_offset: u64,
    pub toc_length: u64,
    pub pyvers: u32,
    pub files: Vec<TOCEntry>,
    pub buffer: Vec<u8>,
}

const PYINST_MAGIC: &[u8] = b"MEI\x0D\x0A\x0B\x0E";

use std::fs::File;
use std::io::Read;
use std::path::Path;

impl PyInstallerArchive {
    /// Attempts to parse a PyInstaller archive from a given file path by searching for the Magic Byte sequence.
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        // Scan backwards to find the magic cookie (often near the end of the exe)
        let magic_pos =
            Self::find_magic(&buffer).ok_or("Not a PyInstaller executable (Magic not found)")?;

        let mut offset = magic_pos + PYINST_MAGIC.len();

        if offset + 16 > buffer.len() {
            return Err("Unexpected EOF while reading PyInstaller headers".into());
        }

        let pkg_length = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as u64;
        offset += 4;
        let toc_offset = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as u64;
        offset += 4;
        let toc_length = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as u64;
        offset += 4;
        let pyvers = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap());

        let absolute_toc_offset =
            (magic_pos as u64 + PYINST_MAGIC.len() as u64).saturating_sub(pkg_length) + toc_offset;
        let mut files = Vec::new();

        if absolute_toc_offset as usize + toc_length as usize <= buffer.len() {
            let mut current = absolute_toc_offset as usize;
            let end = current + toc_length as usize;

            while current + 18 < end {
                let entrylen =
                    u32::from_be_bytes(buffer[current..current + 4].try_into().unwrap()) as usize;

                if entrylen < 18 || current + entrylen > end {
                    break;
                }
                let dpos = u32::from_be_bytes(buffer[current + 4..current + 8].try_into().unwrap());
                let dlen =
                    u32::from_be_bytes(buffer[current + 8..current + 12].try_into().unwrap());
                let ulen =
                    u32::from_be_bytes(buffer[current + 12..current + 16].try_into().unwrap());
                let cmpr = buffer[current + 16];
                let type_cmpr = buffer[current + 17];

                // Read the name string from offset 18 up to null terminator
                let name_start = current + 18;
                let mut name_end = name_start;
                while name_end < current + entrylen && buffer[name_end] != 0 {
                    name_end += 1;
                }

                let name = String::from_utf8_lossy(&buffer[name_start..name_end]).to_string();
                if !name.is_empty() {
                    files.push(TOCEntry {
                        name,
                        dpos,
                        dlen,
                        ulen,
                        cmpr,
                        type_cmpr,
                    });
                }

                current += entrylen;
            }
        }

        Ok(Self {
            magic_offset: magic_pos as u64,
            pkg_length,
            toc_offset,
            toc_length,
            pyvers,
            files,
            buffer,
        })
    }

    /// Extracts a specific file from the PyInstaller archive using the TOC pointer and Zlib decompression if enabled.
    pub fn extract_file(&self, entry: &TOCEntry) -> Result<Vec<u8>, String> {
        let base_offset =
            (self.magic_offset as u64 + PYINST_MAGIC.len() as u64).saturating_sub(self.pkg_length);
        let absolute_data_offset = base_offset + entry.dpos as u64;

        if absolute_data_offset as usize + entry.dlen as usize > self.buffer.len() {
            return Err("Data out of bounds in PyInstaller payload.".to_string());
        }

        let compressed_data = &self.buffer
            [absolute_data_offset as usize..absolute_data_offset as usize + entry.dlen as usize];

        if entry.cmpr == 1 {
            // ZLIB decompression
            use flate2::read::ZlibDecoder;
            let mut decoder = ZlibDecoder::new(compressed_data);
            let mut uncompressed = Vec::with_capacity(entry.ulen as usize);
            decoder
                .read_to_end(&mut uncompressed)
                .map_err(|e| format!("Zlib decompression failed: {}", e))?;
            Ok(uncompressed)
        } else {
            Ok(compressed_data.to_vec())
        }
    }

    // Typical KMP or simple search since the cookie is small
    fn find_magic(buffer: &[u8]) -> Option<usize> {
        buffer
            .windows(PYINST_MAGIC.len())
            .rposition(|window| window == PYINST_MAGIC)
    }
}

/// Native Rust disassembler that parses .pyc bytecodes back into Python opcodes
pub fn decompile_bytecode(data: &[u8]) -> Result<String, String> {
    use crate::python::disasm::Disassembler;
    use crate::python::pyc_parser::PycFile;

    let pyc = PycFile::parse(data)?;
    let disasm = Disassembler::new();
    let insts = disasm.disassemble(&pyc.bytecode);

    Ok(format!("=== Native RvSpy Python Disassembler ===\nMagic: 0x{:X} | Timestamp: {}\n-------------------------------------------------\n{}", 
               pyc.magic, pyc.timestamp, disasm.format(&insts)))
}
