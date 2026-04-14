#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string.h> // Ensure we only import required C headers where possible

// Windows PE Data Structures (Platform-independent definitions to avoid dragging `<windows.h>`)
#pragma pack(1)

struct IMAGE_DOS_HEADER {
  uint16_t e_magic; // Magic number ("MZ")
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  int32_t e_lfanew; // File address of new exe header
};

struct IMAGE_FILE_HEADER {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER32 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// 64-bit Optional Header signature
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B

struct IMAGE_SECTION_HEADER {
  uint8_t Name[8];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

#pragma pack()

extern "C" {

void nuitka_hello() {
  std::cout << "[C++] Nuitka Native Engine Initialized." << std::endl;
}

int scan_for_magic(const uint8_t *buffer, size_t length,
                   const uint8_t *signature, size_t sig_len) {
  if (length < sig_len || sig_len == 0)
    return -1;

  const uint8_t *p = buffer;
  const uint8_t *end = buffer + length - sig_len;

  while (p <= end) {
    // memchr is highly SIMD optimized by the C runtime (AVX2/SSE4)
    p = static_cast<const uint8_t *>(std::memchr(p, signature[0], end - p + 1));
    if (!p)
      break;

    if (std::memcmp(p, signature, sig_len) == 0) {
      return static_cast<int>(p - buffer);
    }
    p++;
  }
  return -1;
}

// Return the number of tuples found, filling offsets and sizes.
int scan_for_tuples(const uint8_t *buffer, size_t length, uint32_t *out_offsets,
                    uint32_t *out_sizes, size_t max_results) {
  int found = 0;
  const uint8_t *p = buffer;
  const uint8_t *end = buffer + length - 10;

  while (p <= end && found < max_results) {
    // Look for 0xB9 which is mov ecx, IMM32
    p = static_cast<const uint8_t *>(std::memchr(p, 0xB9, end - p + 1));
    if (!p)
      break;

    if (p[5] == 0xE8) {
      uint32_t size = p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24);
      if (size > 0 && size < 256) { // Heuristic check
        out_offsets[found] = static_cast<uint32_t>(p - buffer);
        out_sizes[found] = size;
        found++;
        p += 10;
        continue;
      }
    }
    p++;
  }
  return found;
}

int scan_for_cells(const uint8_t *buffer, size_t length, uint32_t *out_offsets,
                   size_t max_results) {
  int found = 0;
  const uint8_t *p = buffer;
  const uint8_t *end = buffer + length - 12;

  while (p <= end && found < max_results) {
    p = static_cast<const uint8_t *>(std::memchr(p, 0x48, end - p + 1));
    if (!p)
      break;

    if (p[1] == 0x8B && p[2] == 0x0D && p[7] == 0xE8) {
      out_offsets[found] = static_cast<uint32_t>(p - buffer);
      found++;
      p += 12;
      continue;
    }
    p++;
  }
  return found;
}

// A struct bridging C++ and Rust
struct SectionInfo {
  char name[8];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
};

/// Analyze PE headers and check if it has properties typical of Nuitka
/// `out_sections` should be a pre-allocated array of SectionInfo from Rust
/// Returns the number of sections populated, 0 if not a PE file, -1 on error.
int parse_pe_headers(const uint8_t *buffer, size_t length,
                     SectionInfo *out_sections, size_t max_sections) {
  if (length < sizeof(IMAGE_DOS_HEADER)) {
    return 0; // File too small
  }

  const IMAGE_DOS_HEADER *dosHeader =
      reinterpret_cast<const IMAGE_DOS_HEADER *>(buffer);

  // Check for 'MZ' signature
  if (dosHeader->e_magic != 0x5a4d) {
    return 0;
  }

  uint32_t ntHeaderOffset = dosHeader->e_lfanew;
  if (ntHeaderOffset + 4 + sizeof(IMAGE_FILE_HEADER) > length) {
    return -1; // Invalid NT header offset
  }

  // Check for 'PE\0\0' signature
  const uint8_t *ntSignature = buffer + ntHeaderOffset;
  if (ntSignature[0] != 'P' || ntSignature[1] != 'E' || ntSignature[2] != 0 ||
      ntSignature[3] != 0) {
    return 0;
  }

  const IMAGE_FILE_HEADER *fileHeader =
      reinterpret_cast<const IMAGE_FILE_HEADER *>(buffer + ntHeaderOffset + 4);

  // Print sections
  uint32_t optionalHeaderSize = fileHeader->SizeOfOptionalHeader;
  const uint8_t *sectionHeaderOffset = buffer + ntHeaderOffset + 4 +
                                       sizeof(IMAGE_FILE_HEADER) +
                                       optionalHeaderSize;

  if (sectionHeaderOffset +
          (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) >
      buffer + length) {
    return -1; // Exceeds boundary
  }

  int written = 0;
  const IMAGE_SECTION_HEADER *sections =
      reinterpret_cast<const IMAGE_SECTION_HEADER *>(sectionHeaderOffset);
  for (int i = 0; i < fileHeader->NumberOfSections && i < max_sections; i++) {
    std::memcpy(out_sections[i].name, sections[i].Name, 8);
    out_sections[i].virtual_size = sections[i].Misc.VirtualSize;
    out_sections[i].virtual_address = sections[i].VirtualAddress;
    out_sections[i].size_of_raw_data = sections[i].SizeOfRawData;
    out_sections[i].pointer_to_raw_data = sections[i].PointerToRawData;
    written++;
  }

  return written;
}

/// Dumps a highly detailed text report of the PE internals
int dump_pe_metadata(const uint8_t *buffer, size_t length, char *out_buffer,
                     size_t max_len) {
  if (length < sizeof(IMAGE_DOS_HEADER) || max_len == 0)
    return -1;
  const IMAGE_DOS_HEADER *dosHeader =
      reinterpret_cast<const IMAGE_DOS_HEADER *>(buffer);
  if (dosHeader->e_magic != 0x5a4d)
    return -1;

  uint32_t ntHeaderOffset = dosHeader->e_lfanew;
  if (ntHeaderOffset + 24 > length)
    return -1;

  const uint8_t *ntSignature = buffer + ntHeaderOffset;
  if (ntSignature[0] != 'P' || ntSignature[1] != 'E' || ntSignature[2] != 0 ||
      ntSignature[3] != 0)
    return -1;

  const IMAGE_FILE_HEADER *fileHeader =
      reinterpret_cast<const IMAGE_FILE_HEADER *>(buffer + ntHeaderOffset + 4);

  int written = 0;
  auto append = [&](const char *format, ...) {
    if (written >= max_len)
      return;
    va_list args;
    va_start(args, format);
    int w = vsnprintf(out_buffer + written, max_len - written, format, args);
    if (w > 0)
      written += w;
    va_end(args);
  };

  append("--- PE Header Dump ---\n");
  append("Machine: 0x%04X\n", fileHeader->Machine);
  append("NumberOfSections: %d\n", fileHeader->NumberOfSections);
  append("TimeDateStamp: 0x%08X\n", fileHeader->TimeDateStamp);
  append("Characteristics: 0x%04X\n\n", fileHeader->Characteristics);

  uint16_t magic =
      *reinterpret_cast<const uint16_t *>(buffer + ntHeaderOffset + 24);
  append("--- Optional Header ---\n");
  append("Magic: 0x%04X (%s)\n", magic,
         magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "PE32");

  const IMAGE_DATA_DIRECTORY *data_dirs = nullptr;
  uint32_t rva_count = 0;

  if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (ntHeaderOffset + 24 + sizeof(IMAGE_OPTIONAL_HEADER64) <= length) {
      const auto *optHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(
          buffer + ntHeaderOffset + 24);
      append("AddressOfEntryPoint: 0x%08X\n", optHeader->AddressOfEntryPoint);
      append("ImageBase: 0x%016llX\n", optHeader->ImageBase);
      append("SectionAlignment: 0x%08X\n", optHeader->SectionAlignment);
      append("FileAlignment: 0x%08X\n", optHeader->FileAlignment);
      append("Subsystem: 0x%04X\n", optHeader->Subsystem);
      append("DllCharacteristics: 0x%04X\n", optHeader->DllCharacteristics);
      data_dirs = optHeader->DataDirectory;
      rva_count = optHeader->NumberOfRvaAndSizes;
    }
  } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    if (ntHeaderOffset + 24 + sizeof(IMAGE_OPTIONAL_HEADER32) <= length) {
      const auto *optHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(
          buffer + ntHeaderOffset + 24);
      append("AddressOfEntryPoint: 0x%08X\n", optHeader->AddressOfEntryPoint);
      append("ImageBase: 0x%08X\n", optHeader->ImageBase);
      append("SectionAlignment: 0x%08X\n", optHeader->SectionAlignment);
      append("FileAlignment: 0x%08X\n", optHeader->FileAlignment);
      append("Subsystem: 0x%04X\n", optHeader->Subsystem);
      append("DllCharacteristics: 0x%04X\n", optHeader->DllCharacteristics);
      data_dirs = optHeader->DataDirectory;
      rva_count = optHeader->NumberOfRvaAndSizes;
    }
  }

  if (data_dirs && rva_count > 0) {
    append("\n--- Data Directories ---\n");
    const char *names[] = {
        "Export",    "Import",      "Resource",      "Exception",
        "Security",  "BaseReloc",   "Debug",         "Architecture",
        "GlobalPtr", "TLS",         "LoadConfig",    "BoundImport",
        "IAT",       "DelayImport", "COMDescriptor", "Reserved"};
    for (uint32_t i = 0; i < rva_count && i < 16; i++) {
      if (data_dirs[i].VirtualAddress != 0) {
        append("%-15s RVA: 0x%08X  Size: 0x%08X\n", names[i],
               data_dirs[i].VirtualAddress, data_dirs[i].Size);
      }
    }
  }

  append("\n--- PE Sections ---\n");
  uint32_t optionalHeaderSize = fileHeader->SizeOfOptionalHeader;
  const uint8_t *sectionHeaderOffset =
      buffer + ntHeaderOffset + 24 + optionalHeaderSize;
  const IMAGE_SECTION_HEADER *sections =
      reinterpret_cast<const IMAGE_SECTION_HEADER *>(sectionHeaderOffset);

  if (sectionHeaderOffset +
          (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <=
      buffer + length) {
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
      char name[9] = {0};
      std::memcpy(name, sections[i].Name, 8);
      append("Section %-8s | VAddr: 0x%08X | VSize: 0x%08X | RawAddr: 0x%08X | "
             "RawSize: 0x%08X\n",
             name, sections[i].VirtualAddress, sections[i].Misc.VirtualSize,
             sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }
  }

  return written;
}
}
