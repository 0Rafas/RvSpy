use goblin::pe::PE;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct DeepPEInformation {
    pub dos_header: Vec<(String, String)>,
    pub file_header: Vec<(String, String)>,
    pub optional_header: Vec<(String, String)>,
    pub sections: Vec<DeepSectionInfo>,
    pub packer_detected: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct DeepSectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

pub fn extract_deep_pe(file_data: &[u8]) -> Result<DeepPEInformation, String> {
    let pe = match PE::parse(file_data) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to parse PE: {}", e)),
    };

    let dos_header = vec![
        (
            "e_magic".to_string(),
            format!("0x{:04X}", pe.header.dos_header.signature),
        ),
        (
            "e_cblp".to_string(),
            format!("0x{:04X}", pe.header.dos_header.bytes_on_last_page),
        ),
        (
            "e_cp".to_string(),
            format!("0x{:04X}", pe.header.dos_header.pages_in_file),
        ),
        (
            "e_crlc".to_string(),
            format!("0x{:04X}", pe.header.dos_header.relocations),
        ),
        (
            "e_cparhdr".to_string(),
            format!(
                "0x{:04X}",
                pe.header.dos_header.size_of_header_in_paragraphs
            ),
        ),
        (
            "e_minalloc".to_string(),
            format!(
                "0x{:04X}",
                pe.header.dos_header.minimum_extra_paragraphs_needed
            ),
        ),
        (
            "e_maxalloc".to_string(),
            format!(
                "0x{:04X}",
                pe.header.dos_header.maximum_extra_paragraphs_needed
            ),
        ),
        (
            "e_ss".to_string(),
            format!("0x{:04X}", pe.header.dos_header.initial_relative_ss),
        ),
        (
            "e_sp".to_string(),
            format!("0x{:04X}", pe.header.dos_header.initial_sp),
        ),
        (
            "e_csum".to_string(),
            format!("0x{:04X}", pe.header.dos_header.checksum),
        ),
        (
            "e_ip".to_string(),
            format!("0x{:04X}", pe.header.dos_header.initial_ip),
        ),
        (
            "e_cs".to_string(),
            format!("0x{:04X}", pe.header.dos_header.initial_relative_cs),
        ),
        (
            "e_lfarlc".to_string(),
            format!(
                "0x{:04X}",
                pe.header.dos_header.file_address_of_relocation_table
            ),
        ),
        (
            "e_ovno".to_string(),
            format!("0x{:04X}", pe.header.dos_header.overlay_number),
        ),
        (
            "e_lfanew".to_string(),
            format!("0x{:08X}", pe.header.dos_header.pe_pointer),
        ),
    ];

    let file_header = vec![
        (
            "Machine".to_string(),
            format!("0x{:04X}", pe.header.coff_header.machine),
        ),
        (
            "NumberOfSections".to_string(),
            format!("0x{:04X}", pe.header.coff_header.number_of_sections),
        ),
        (
            "TimeDateStamp".to_string(),
            format!("0x{:08X}", pe.header.coff_header.time_date_stamp),
        ),
        (
            "PointerToSymbolTable".to_string(),
            format!("0x{:08X}", pe.header.coff_header.pointer_to_symbol_table),
        ),
        (
            "NumberOfSymbols".to_string(),
            format!("0x{:08X}", pe.header.coff_header.number_of_symbol_table),
        ),
        (
            "SizeOfOptionalHeader".to_string(),
            format!("0x{:04X}", pe.header.coff_header.size_of_optional_header),
        ),
        (
            "Characteristics".to_string(),
            format!("0x{:04X}", pe.header.coff_header.characteristics),
        ),
    ];

    let mut optional_header = Vec::new();
    if let Some(opt) = pe.header.optional_header {
        optional_header.push((
            "MajorLinkerVersion".to_string(),
            format!("0x{:02X}", opt.standard_fields.major_linker_version),
        ));
        optional_header.push((
            "MinorLinkerVersion".to_string(),
            format!("0x{:02X}", opt.standard_fields.minor_linker_version),
        ));
        optional_header.push((
            "SizeOfCode".to_string(),
            format!("0x{:08X}", opt.standard_fields.size_of_code),
        ));
        optional_header.push((
            "SizeOfInitializedData".to_string(),
            format!("0x{:08X}", opt.standard_fields.size_of_initialized_data),
        ));
        optional_header.push((
            "SizeOfUninitializedData".to_string(),
            format!("0x{:08X}", opt.standard_fields.size_of_uninitialized_data),
        ));
        optional_header.push((
            "AddressOfEntryPoint".to_string(),
            format!("0x{:08X}", opt.standard_fields.address_of_entry_point),
        ));
        optional_header.push((
            "BaseOfCode".to_string(),
            format!("0x{:08X}", opt.standard_fields.base_of_code),
        ));

        optional_header.push((
            "ImageBase".to_string(),
            format!("0x{:016X}", opt.windows_fields.image_base),
        ));
        optional_header.push((
            "SectionAlignment".to_string(),
            format!("0x{:08X}", opt.windows_fields.section_alignment),
        ));
        optional_header.push((
            "FileAlignment".to_string(),
            format!("0x{:08X}", opt.windows_fields.file_alignment),
        ));
        optional_header.push((
            "MajorOperatingSystemVersion".to_string(),
            format!(
                "0x{:04X}",
                opt.windows_fields.major_operating_system_version
            ),
        ));
        optional_header.push((
            "MinorOperatingSystemVersion".to_string(),
            format!(
                "0x{:04X}",
                opt.windows_fields.minor_operating_system_version
            ),
        ));
        optional_header.push((
            "SizeOfImage".to_string(),
            format!("0x{:08X}", opt.windows_fields.size_of_image),
        ));
        optional_header.push((
            "SizeOfHeaders".to_string(),
            format!("0x{:08X}", opt.windows_fields.size_of_headers),
        ));
        optional_header.push((
            "CheckSum".to_string(),
            format!("0x{:08X}", opt.windows_fields.check_sum),
        ));
        optional_header.push((
            "Subsystem".to_string(),
            format!("0x{:04X}", opt.windows_fields.subsystem),
        ));
        optional_header.push((
            "DllCharacteristics".to_string(),
            format!("0x{:04X}", opt.windows_fields.dll_characteristics),
        ));
    }

    let mut sections = Vec::new();
    for sec in pe.sections {
        sections.push(DeepSectionInfo {
            name: String::from_utf8_lossy(&sec.name)
                .trim_end_matches('\0')
                .to_string(),
            virtual_size: sec.virtual_size,
            virtual_address: sec.virtual_address,
            size_of_raw_data: sec.size_of_raw_data,
            pointer_to_raw_data: sec.pointer_to_raw_data,
            pointer_to_relocations: sec.pointer_to_relocations,
            pointer_to_linenumbers: sec.pointer_to_linenumbers,
            number_of_relocations: sec.number_of_relocations,
            number_of_linenumbers: sec.number_of_linenumbers,
            characteristics: sec.characteristics,
        });
    }

    // Advanced Packer / Compiler Detection Heuristics (DIE Equivalent)
    let mut packer_detection = "Unknown / Native (C/C++/Rust)".to_string();
    
    // Check Section Names
    for sec in &sections {
        let name = sec.name.to_lowercase();
        if name.contains("upx") {
            packer_detection = "UPX Packer".to_string();
            break;
        } else if name == ".pyinst" || name == ".ndata" { // Sometimes ND is Nuitka Data, but PyInstaller is clear
            packer_detection = "PyInstaller".to_string();
            break;
        } else if name == ".vmp0" || name == ".vmp1" {
            packer_detection = "VMProtect".to_string();
            break;
        } else if name == ".themida" {
            packer_detection = "Themida".to_string();
            break;
        }
    }

    // Check raw Byte Signatures / Strings for freezers
    if packer_detection == "Unknown / Native (C/C++/Rust)" {
        let mut pyinstaller = false;
        let mut nuitka = false;
        let mut py2exe = false;
        let mut cx_freeze = false;

        // Slide window over file for ASCII magic markers
        let mut window = file_data.windows(8);
        while let Some(w) = window.next() {
            // "MEI\0" "PYTHONS"  are common inside PyInstaller blobs
            if w.starts_with(b"MEI\0") || w.starts_with(b"PYTHONSCR") || w.starts_with(b"_MEIPASS") {
                pyinstaller = true;
                break;
            } else if w.starts_with(b"Nuitka_S") || w.starts_with(b"compiled_") || w.starts_with(b"__nuitka") {
                nuitka = true;
                break;
            } else if w.starts_with(b"PY2EXE_V") {
                py2exe = true;
                break;
            } else if w.starts_with(b"cx_Freez") {
                cx_freeze = true;
                break;
            }
        }
        
        // Final fallback checks if we parsed imports (PE-goblin has imports but we can just use raw parsing or flags)
        // Here we rely on the byte scanners and section mappings.
        if pyinstaller { packer_detection = "PyInstaller Executable".to_string(); }
        else if nuitka { packer_detection = "Nuitka Native Python Compiler".to_string(); }
        else if cx_freeze { packer_detection = "cx_Freeze Python Binary".to_string(); }
        else if py2exe { packer_detection = "py2exe Binary".to_string(); }
    }

    Ok(DeepPEInformation {
        dos_header,
        file_header,
        optional_header,
        sections,
        packer_detected: packer_detection,
    })
}
