use crate::core::debugger::RegisterContext;

pub struct RvEmulator;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EmulationResult {
    pub final_context: RegisterContext,
    pub instructions_executed: u64,
    pub memory_mutations: Vec<(u64, u8, u8)>, // (address, old_value, new_value)
}

impl RvEmulator {
    pub fn new() -> Result<Self, String> {
        // Unicorn Engine is disabled until LLVM/libclang is installed.
        Err(
            "Unicorn Engine is not available. To enable: winget install LLVM.LLVM".to_string()
        )
    }

    /// Emulates a block of machine code in an isolated sandboxed environment.
    pub fn emulate_block(
        &mut self,
        _code: &[u8],
        _context: RegisterContext,
    ) -> Result<EmulationResult, String> {
        Err("Emulation not available - Unicorn Engine requires LLVM/libclang.".to_string())
    }
}

/// Checks whether full Unicorn emulation is available on this system.
pub fn is_emulation_available() -> bool {
    false
}
