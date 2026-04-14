

#[repr(C)]
#[derive(Debug)]
pub struct SectionInfo {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct NativeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

extern "C" {
    // Declared in c_src/nuitka_analyzer.cpp
    fn nuitka_hello();
    fn scan_for_magic(
        buffer: *const u8,
        length: usize,
        signature: *const u8,
        sig_len: usize,
    ) -> i32;
    fn parse_pe_headers(
        buffer: *const u8,
        length: usize,
        out_sections: *mut SectionInfo,
        max_sections: usize,
    ) -> i32;
    fn dump_pe_metadata(
        buffer: *const u8,
        length: usize,
        out_buffer: *mut i8,
        max_len: usize,
    ) -> i32;
    fn scan_for_tuples(
        buffer: *const u8,
        length: usize,
        out_offsets: *mut u32,
        out_sizes: *mut u32,
        max_results: usize,
    ) -> i32;
    fn scan_for_cells(
        buffer: *const u8,
        length: usize,
        out_offsets: *mut u32,
        max_results: usize,
    ) -> i32;
}

pub struct NuitkaAnalyzer;

impl NuitkaAnalyzer {
    pub fn init() {
        println!("[RUST] Initializing Nuitka Native Engine...");
        unsafe {
            nuitka_hello();
        }
    }

    pub fn parse_pe(data: &[u8]) -> Result<Vec<NativeSection>, String> {
        let mut sections_buffer: Vec<SectionInfo> = Vec::with_capacity(32); // Max 32 sections

        let res = unsafe {
            parse_pe_headers(data.as_ptr(), data.len(), sections_buffer.as_mut_ptr(), 32)
        };

        if res > 0 {
            unsafe { sections_buffer.set_len(res as usize) };
            let mut extracted = Vec::new();

            for sec in sections_buffer {
                // Parse null-terminated or exact 8-byte char array
                let name = if let Some(null_pos) = sec.name.iter().position(|&c| c == 0) {
                    String::from_utf8_lossy(&sec.name[..null_pos]).into_owned()
                } else {
                    String::from_utf8_lossy(&sec.name).into_owned()
                };

                extracted.push(NativeSection {
                    name,
                    virtual_size: sec.virtual_size,
                    virtual_address: sec.virtual_address,
                    size_of_raw_data: sec.size_of_raw_data,
                    pointer_to_raw_data: sec.pointer_to_raw_data,
                });
            }
            Ok(extracted)
        } else if res == 0 {
            Err("Not a valid PE executable.".to_string())
        } else {
            Err("Malformed PE Header or bounds exceeded.".to_string())
        }
    }

    /// Fast scan wrapper calling the native C++ loop
    pub fn fast_scan(data: &[u8], signature: &[u8]) -> Option<usize> {
        let res = unsafe {
            scan_for_magic(
                data.as_ptr(),
                data.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };
        if res >= 0 {
            Some(res as usize)
        } else {
            None
        }
    }

    pub fn fast_scan_tuples(data: &[u8]) -> Vec<(u32, u32)> {
        let max_results = 2000;
        let mut out_offsets: Vec<u32> = vec![0; max_results];
        let mut out_sizes: Vec<u32> = vec![0; max_results];

        let res = unsafe {
            scan_for_tuples(
                data.as_ptr(),
                data.len(),
                out_offsets.as_mut_ptr(),
                out_sizes.as_mut_ptr(),
                max_results,
            )
        };

        let mut results = Vec::new();
        if res > 0 {
            for i in 0..(res as usize) {
                results.push((out_offsets[i], out_sizes[i]));
            }
        }
        results
    }

    pub fn fast_scan_cells(data: &[u8]) -> Vec<u32> {
        let max_results = 2000;
        let mut out_offsets: Vec<u32> = vec![0; max_results];

        let res = unsafe {
            scan_for_cells(
                data.as_ptr(),
                data.len(),
                out_offsets.as_mut_ptr(),
                max_results,
            )
        };

        let mut results = Vec::new();
        if res > 0 {
            for i in 0..(res as usize) {
                results.push(out_offsets[i]);
            }
        }
        results
    }

    /// Extensively dumps PE metadata directly via the C++ backend
    pub fn get_metadata_dump(data: &[u8]) -> Result<String, String> {
        let max_len = 16384;
        let mut out_buf: Vec<i8> = vec![0; max_len];

        let written =
            unsafe { dump_pe_metadata(data.as_ptr(), data.len(), out_buf.as_mut_ptr(), max_len) };

        if written > 0 {
            let u8_slice = unsafe {
                std::slice::from_raw_parts(out_buf.as_ptr() as *const u8, written as usize)
            };
            Ok(String::from_utf8_lossy(u8_slice).into_owned())
        } else {
            Err("Failed to extract deep PE Metadata.".to_string())
        }
    }
}
