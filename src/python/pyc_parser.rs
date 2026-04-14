#![allow(dead_code)]
use std::io::{Cursor, Read};

#[derive(Debug, Clone)]
pub struct PycFile {
    pub magic: u32,
    pub bitfield: u32,
    pub timestamp: u32,
    pub size: u32,
    pub hash: Vec<u8>,
    pub bytecode: Vec<u8>,
}

impl PycFile {
    /// Strips the 16-byte header from a modern Python >3.7 .pyc file and returns the PycFile struct and unmarshaled CodeObject bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(data);

        let mut magic = [0u8; 4];
        if cursor.read_exact(&mut magic).is_err() {
            return Err("Invalid Pyc: too small to hold Magic header".to_string());
        }
        let magic_val = u32::from_le_bytes(magic);

        // Python 3.7+ format uses 16 byte header instead of 12 byte
        // Format: Magic (4) | Bitfield (4) | Timestamp (4) | File Size (4)

        let mut bitfield = [0u8; 4];
        let mut timestamp = [0u8; 4];
        let mut size = [0u8; 4];

        // Optional reading (if 16 byte)
        let mut _is_pep_552 = false;
        if cursor.read_exact(&mut bitfield).is_ok() {
            if bitfield != [0; 4] {
                _is_pep_552 = true; // Hash based pyc
            }
        } else {
            return Err("Invalid Pyc: Failed to read bitfield".to_string());
        }

        if cursor.read_exact(&mut timestamp).is_err() {
            return Err("Invalid Pyc: Failed to read timestamp".to_string());
        }
        if cursor.read_exact(&mut size).is_err() {
            return Err("Invalid Pyc: Failed to read size".to_string());
        }

        let current_pos = cursor.position() as usize;
        let bytecode = data[current_pos..].to_vec();

        Ok(PycFile {
            magic: magic_val,
            bitfield: u32::from_le_bytes(bitfield),
            timestamp: u32::from_le_bytes(timestamp),
            size: u32::from_le_bytes(size),
            hash: Vec::new(),
            bytecode,
        })
    }
}
