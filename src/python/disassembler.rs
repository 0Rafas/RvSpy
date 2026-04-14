use capstone::prelude::*;

pub fn disassemble_x86_64(code: &[u8], base_address: u64) -> Result<String, String> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .map_err(|e| format!("Failed to initialize Capstone: {}", e))?;

    let insns = cs
        .disasm_all(code, base_address)
        .map_err(|e| format!("Disassembly failed: {}", e))?;

    let mut out = String::with_capacity(code.len() * 16);

    // Header
    out.push_str("RvSpy Advanced Disassembler (x86_64) - Capstone Engine\n");
    out.push_str("=========================================================\n\n");

    for i in insns.as_ref() {
        let addr = i.address();
        let mnemonic = i.mnemonic().unwrap_or("???");
        let op_str = i.op_str().unwrap_or("");

        // Print instruction bytes alongside the instruction
        let bytes = i.bytes();
        let mut hex_bytes = String::with_capacity(16);
        for b in bytes.iter().take(8) {
            hex_bytes.push_str(&format!("{:02X} ", b));
        }
        if bytes.len() > 8 {
            hex_bytes.push_str(".. ");
        }

        out.push_str(&format!(
            "0x{:016X}: {:<24} {:<8} {}\n",
            addr, hex_bytes, mnemonic, op_str
        ));
    }

    Ok(out)
}
