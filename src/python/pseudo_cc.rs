use capstone::prelude::*;

/// Provides a very basic, heuristic "Pseudo-C++" lifting of AMD64 assembly instructions
/// for easier readability. It maps registers to variables and creates C-like assignments.
pub fn decompile_pseudo_c(
    code: &[u8],
    base_address: u64,
    enable_loop_recovery: bool,
    enable_auto_var_naming: bool,
    enable_calling_conventions: bool,
) -> Result<String, String> {
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

    let mut backward_jumps: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut loop_ends: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();

    if enable_loop_recovery {
        for i in insns.as_ref() {
            let addr = i.address();
            let mnemonic = i.mnemonic().unwrap_or("");
            if mnemonic.starts_with("j") && mnemonic != "jmp" {
                if let Some(op_str) = i.op_str() {
                    let dest_str = op_str.replace("0x", "");
                    if let Ok(dest_addr) = u64::from_str_radix(&dest_str, 16) {
                        if dest_addr < addr {
                            backward_jumps.insert(dest_addr);
                            loop_ends.insert(addr, dest_addr);
                        }
                    }
                }
            }
        }
    }

    out.push_str("// RvSpy Pseudo-C++ Engine (Heuristic Lifter)\n");
    out.push_str("// Note: Control flow graphs are simplified.\n");
    out.push_str("==============================================\n\n");

    out.push_str("void sub_function() {\n");

    for i in insns.as_ref() {
        let addr = i.address();

        if enable_loop_recovery && backward_jumps.contains(&addr) {
            out.push_str(&format!("  /* {:<8X} */  do {{\n", addr));
        }

        let mnemonic = i.mnemonic().unwrap_or("");
        let op_str = i.op_str().unwrap_or("");

        // Basic Heuristic Translation
        let mut pseudo_line = String::new();

        let ops: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();

        match mnemonic {
            "mov" | "movzx" | "movsx" | "lea" => {
                if ops.len() == 2 {
                    let dest =
                        format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions);
                    let src =
                        format_operand(ops[1], enable_auto_var_naming, enable_calling_conventions);

                    if mnemonic == "lea" {
                        pseudo_line =
                            format!("{} = &({});", dest, src.replace('[', "").replace(']', ""));
                    } else {
                        pseudo_line = format!("{} = {};", dest, src);
                    }
                }
            }
            "add" | "sub" | "imul" | "xor" | "or" | "and" => {
                if ops.len() == 2 {
                    let dest =
                        format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions);
                    let src =
                        format_operand(ops[1], enable_auto_var_naming, enable_calling_conventions);
                    let operator = match mnemonic {
                        "add" => "+=",
                        "sub" => "-=",
                        "imul" => "*=",
                        "xor" => "^=",
                        "or" => "|=",
                        "and" => "&=",
                        _ => "?=",
                    };

                    if dest == src && mnemonic == "xor" {
                        pseudo_line = format!("{} = 0; // xor self", dest);
                    } else {
                        pseudo_line = format!("{} {} {};", dest, operator, src);
                    }
                }
            }
            "inc" => {
                if ops.len() == 1 {
                    pseudo_line = format!(
                        "{}++;",
                        format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions)
                    );
                }
            }
            "dec" => {
                if ops.len() == 1 {
                    pseudo_line = format!(
                        "{}--;",
                        format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions)
                    );
                }
            }
            "cmp" | "test" => {
                if ops.len() == 2 {
                    pseudo_line = format!(
                        "// flag = {} == {}",
                        format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions),
                        format_operand(ops[1], enable_auto_var_naming, enable_calling_conventions)
                    );
                }
            }
            "jmp" => {
                pseudo_line = format!("goto loc_{};", ops[0].replace("0x", ""));
            }
            "je" | "jz" | "jne" | "jnz" | "ja" | "jg" | "jb" | "jl" => {
                let dest_str = ops[0].replace("0x", "");
                let condition = match mnemonic {
                    "je" | "jz" => "FLAG_EQUAL",
                    "jne" | "jnz" => "!FLAG_EQUAL",
                    "ja" | "jg" => "FLAG_GREATER",
                    "jb" | "jl" => "FLAG_LESS",
                    _ => "UNKNOWN",
                };

                if enable_loop_recovery && loop_ends.contains_key(&addr) {
                    pseudo_line = format!(
                        "}} while({}); // backward loop to loc_{}",
                        condition, dest_str
                    );
                } else {
                    pseudo_line = format!("if ({}) goto loc_{};", condition, dest_str);
                }
            }
            "call" => {
                if ops.len() == 1 {
                    pseudo_line = format!("sub_{}();", ops[0].replace("0x", ""));
                }
            }
            "ret" => {
                pseudo_line = format!("return v_rax;");
            }
            "push" => {
                pseudo_line = format!(
                    "stack.push({});",
                    format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions)
                )
            }
            "pop" => {
                pseudo_line = format!(
                    "{} = stack.pop();",
                    format_operand(ops[0], enable_auto_var_naming, enable_calling_conventions)
                )
            }
            "nop" => pseudo_line = String::from("// nop"),
            _ => {
                pseudo_line = format!("__asm(\"{} {}\");", mnemonic, op_str);
            }
        }

        if !(enable_loop_recovery && loop_ends.contains_key(&addr)) {
            let prefix =
                if enable_loop_recovery && backward_jumps.iter().any(|&target| addr > target) {
                    "    "
                } else {
                    ""
                };
            out.push_str(&format!(
                "  /* {:<8X} */  {}{}\n",
                addr, prefix, pseudo_line
            ));
        } else {
            out.push_str(&format!("  /* {:<8X} */  {}\n", addr, pseudo_line));
        }
    }

    out.push_str("}\n");

    Ok(out)
}

fn format_operand(op: &str, enable_auto_var: bool, enable_calling_conv: bool) -> String {
    let mut s = op.to_string();

    // Replace pointer sizes
    s = s.replace("qword ptr ", "(uint64_t*)");
    s = s.replace("dword ptr ", "(uint32_t*)");
    s = s.replace("word ptr ", "(uint16_t*)");
    s = s.replace("byte ptr ", "(uint8_t*)");

    // Add v_ prefix to known registers to make it look like a variable
    let regs = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d",
        "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "bp",
        "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "al", "bl", "cl", "dl",
        "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    ];

    for r in regs {
        let replace_str = if enable_calling_conv {
            match r {
                "rcx" | "ecx" => "arg_1".to_string(),
                "rdx" | "edx" => "arg_2".to_string(),
                "r8" | "r8d" => "arg_3".to_string(),
                "r9" | "r9d" => "arg_4".to_string(),
                _ => format!("v_{}", r),
            }
        } else {
            format!("v_{}", r)
        };

        // We simulate basic boundary check manually for performance instead of Regex
        if s.contains(r) {
            let tokens: Vec<&str> = s.split(|c: char| !c.is_alphanumeric()).collect();
            if tokens.contains(&r) {
                s = s.replace(r, &replace_str);
            }
        }
    }

    if enable_auto_var {
        // Very basic heuristic to catch `[v_rbp - 0x??]` or `[v_rsp + 0x??]`
        // Since we already replaced `rbp` with `v_rbp`, look for that.
        if s.contains("[v_rbp - 0x") {
            let parts: Vec<&str> = s.split("[v_rbp - 0x").collect();
            if parts.len() == 2 {
                let hex_part_end = parts[1].find(']').unwrap_or(0);
                if hex_part_end > 0 {
                    let hex_val = &parts[1][..hex_part_end];
                    s = format!("local_var_{}", hex_val);
                }
            }
        } else if s.contains("[v_rsp + 0x") {
            let parts: Vec<&str> = s.split("[v_rsp + 0x").collect();
            if parts.len() == 2 {
                let hex_part_end = parts[1].find(']').unwrap_or(0);
                if hex_part_end > 0 {
                    let hex_val = &parts[1][..hex_part_end];
                    s = format!("local_var_{}", hex_val);
                }
            }
        } else if s.contains("[v_rbp + 0x") {
            let parts: Vec<&str> = s.split("[v_rbp + 0x").collect();
            if parts.len() == 2 {
                let hex_part_end = parts[1].find(']').unwrap_or(0);
                if hex_part_end > 0 {
                    let hex_val = &parts[1][..hex_part_end];
                    s = format!("arg_stack_{}", hex_val);
                }
            }
        }
    }

    s
}
