#![allow(dead_code)]
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: u8,
    pub opname: String,
    pub arg: Option<u16>,
    pub arg_val: Option<String>,
}

pub struct Disassembler {
    opcodes: HashMap<u8, &'static str>,
    has_arg: Vec<u8>,
}

impl Disassembler {
    pub fn new() -> Self {
        let mut opcodes = HashMap::new();
        // Python 3.8+ Common Opcodes (Basic Set for now)
        opcodes.insert(1, "POP_TOP");
        opcodes.insert(2, "ROT_TWO");
        opcodes.insert(3, "ROT_THREE");
        opcodes.insert(4, "DUP_TOP");
        opcodes.insert(5, "DUP_TOP_TWO");
        opcodes.insert(9, "NOP");
        opcodes.insert(10, "UNARY_POSITIVE");
        opcodes.insert(11, "UNARY_NEGATIVE");
        opcodes.insert(12, "UNARY_NOT");
        opcodes.insert(15, "UNARY_INVERT");
        opcodes.insert(19, "BINARY_POWER");
        opcodes.insert(20, "BINARY_MULTIPLY");
        opcodes.insert(22, "BINARY_MODULO");
        opcodes.insert(23, "BINARY_ADD");
        opcodes.insert(24, "BINARY_SUBTRACT");
        opcodes.insert(25, "BINARY_SUBSCR");
        opcodes.insert(26, "BINARY_FLOOR_DIVIDE");
        opcodes.insert(27, "BINARY_TRUE_DIVIDE");
        opcodes.insert(28, "INPLACE_FLOOR_DIVIDE");
        opcodes.insert(29, "INPLACE_TRUE_DIVIDE");
        opcodes.insert(50, "GET_AITER");
        opcodes.insert(51, "GET_ANEXT");
        opcodes.insert(52, "BEFORE_ASYNC_WITH");
        opcodes.insert(55, "INPLACE_ADD");
        opcodes.insert(56, "INPLACE_SUBTRACT");
        opcodes.insert(57, "INPLACE_MULTIPLY");
        opcodes.insert(59, "INPLACE_MODULO");
        opcodes.insert(60, "STORE_SUBSCR");
        opcodes.insert(61, "DELETE_SUBSCR");
        opcodes.insert(67, "INPLACE_POWER");
        opcodes.insert(68, "GET_ITER");
        opcodes.insert(69, "GET_YIELD_FROM_ITER");
        opcodes.insert(70, "PRINT_EXPR");
        opcodes.insert(71, "LOAD_BUILD_CLASS");
        opcodes.insert(72, "YIELD_FROM");
        opcodes.insert(73, "GET_AWAITABLE");
        opcodes.insert(74, "LOAD_ASSERTION_ERROR");
        opcodes.insert(75, "INPLACE_LSHIFT");
        opcodes.insert(77, "INPLACE_RSHIFT");
        opcodes.insert(78, "INPLACE_AND");
        opcodes.insert(79, "INPLACE_XOR");
        opcodes.insert(80, "INPLACE_OR");
        opcodes.insert(83, "RETURN_VALUE");
        opcodes.insert(84, "IMPORT_STAR");
        opcodes.insert(86, "SETUP_ANNOTATIONS");
        opcodes.insert(87, "YIELD_VALUE");
        opcodes.insert(89, "POP_BLOCK");
        opcodes.insert(90, "STORE_NAME");
        opcodes.insert(91, "DELETE_NAME");
        opcodes.insert(92, "UNPACK_SEQUENCE");
        opcodes.insert(93, "FOR_ITER");
        opcodes.insert(94, "UNPACK_EX");
        opcodes.insert(95, "STORE_ATTR");
        opcodes.insert(96, "DELETE_ATTR");
        opcodes.insert(97, "STORE_GLOBAL");
        opcodes.insert(98, "DELETE_GLOBAL");
        opcodes.insert(100, "LOAD_CONST");
        opcodes.insert(101, "LOAD_NAME");
        opcodes.insert(102, "BUILD_TUPLE");
        opcodes.insert(103, "BUILD_LIST");
        opcodes.insert(104, "BUILD_SET");
        opcodes.insert(105, "BUILD_MAP");
        opcodes.insert(106, "LOAD_ATTR");
        opcodes.insert(107, "COMPARE_OP");
        opcodes.insert(108, "IMPORT_NAME");
        opcodes.insert(109, "IMPORT_FROM");
        opcodes.insert(110, "JUMP_FORWARD");
        opcodes.insert(111, "JUMP_IF_FALSE_OR_POP");
        opcodes.insert(112, "JUMP_IF_TRUE_OR_POP");
        opcodes.insert(113, "JUMP_ABSOLUTE");
        opcodes.insert(114, "POP_JUMP_IF_FALSE");
        opcodes.insert(115, "POP_JUMP_IF_TRUE");
        opcodes.insert(116, "LOAD_GLOBAL");
        opcodes.insert(118, "SETUP_FINALLY");
        opcodes.insert(122, "SETUP_WITH");
        opcodes.insert(124, "LOAD_FAST");
        opcodes.insert(125, "STORE_FAST");
        opcodes.insert(126, "DELETE_FAST");
        opcodes.insert(130, "RAISE_VARARGS");
        opcodes.insert(131, "CALL_FUNCTION");
        opcodes.insert(132, "MAKE_FUNCTION");
        opcodes.insert(133, "BUILD_SLICE");
        opcodes.insert(134, "MAKE_CLOSURE");
        opcodes.insert(135, "LOAD_CLOSURE");
        opcodes.insert(136, "LOAD_DEREF");
        opcodes.insert(137, "STORE_DEREF");
        opcodes.insert(140, "CALL_FUNCTION_VAR");
        opcodes.insert(141, "CALL_FUNCTION_KW");
        opcodes.insert(142, "CALL_FUNCTION_VAR_KW");
        opcodes.insert(160, "LOAD_METHOD");
        opcodes.insert(161, "CALL_METHOD");

        // Opcodes >= 90 typically have arguments in Python 3.8
        let has_arg = (90..=255).collect();

        Self { opcodes, has_arg }
    }

    pub fn disassemble(&self, bytecode: &[u8]) -> Vec<Instruction> {
        let mut insts = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            let opcode = bytecode[i];
            let opname = self.opcodes.get(&opcode).unwrap_or(&"UNKNOWN").to_string();

            let mut arg = None;
            let mut step = 1;

            // In Python 3.6+, all instructions are 2 bytes (opcode + arg)
            if i + 1 < bytecode.len() {
                arg = Some(bytecode[i + 1] as u16);
                step = 2;
            }

            insts.push(Instruction {
                offset: i,
                opcode,
                opname,
                arg,
                arg_val: None, // Will eventually resolve consts
            });

            i += step;
        }

        insts
    }

    pub fn format(&self, insts: &[Instruction]) -> String {
        let mut out = String::new();
        for inst in insts {
            if let Some(arg) = inst.arg {
                out.push_str(&format!("{:>4} {:<20} {}\n", inst.offset, inst.opname, arg));
            } else {
                out.push_str(&format!("{:>4} {:<20}\n", inst.offset, inst.opname));
            }
        }
        out
    }
}
