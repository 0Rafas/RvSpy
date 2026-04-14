fn main() {
    println!("cargo:rerun-if-changed=c_src/nuitka_analyzer.cpp");
    println!("cargo:rerun-if-changed=asm_src/scanner.asm");

    let mut build = cc::Build::new();

    // Compile the C++ Engine
    build
        .cpp(true)
        .file("c_src/nuitka_analyzer.cpp")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("/std:c++17") // For MSVC
        .compile("rvspy_core");

    // NOTE: For MASM (.asm on Windows), `cc` might need specific targeting or NASM
    // depending on the project setup. For now, we will add the C++ core. If we use MASM:
    // cc::Build::new().file("asm_src/scanner.asm").compile("rvspy_asm");
}
