use std::ffi::CString;
use capstone::prelude::*;
use std::mem;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::mpsc::{self, Sender, Receiver};

use winapi::shared::minwindef::{FALSE, LPVOID};
use winapi::um::debugapi::{ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, WaitForDebugEvent};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::minwinbase::{
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT
};
use winapi::um::processthreadsapi::{
    CreateProcessA, OpenProcess, PROCESS_INFORMATION, GetThreadContext, SetThreadContext, OpenThread, STARTUPINFOA
};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winbase::{CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS};
use winapi::um::winnt::{
    CONTEXT, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE, PROCESS_ALL_ACCESS, 
    CONTEXT_ALL, THREAD_ALL_ACCESS
};

const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

const EFLAGS_TF: u32 = 0x100; // Trap Flag

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct RegisterContext {
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub stack_locals: Vec<u64>,
}

pub enum DebuggerEvent {
    ProcessLaunched(u32), // PID
    ProcessAttached(u32), // PID
    BreakpointHit { 
        address: usize, 
        thread_id: u32, 
        context: Option<RegisterContext>, 
        disasm: String, 
        hex_dump: String,
        symbol_name: Option<String>,
    },
    ProcessExited(u32),
    LogMessage(String),
}

#[allow(dead_code)]
pub enum DebuggerCommand {
    Launch(String),
    Attach(u32),
    Detach,
    Continue,
    StepInto,
    ToggleBreakpoint(usize),
}

pub struct DebuggerState {
    pub is_active: bool,
    pub target_pid: Option<u32>,
    pub breakpoints: std::collections::HashMap<usize, u8>, // address -> original byte
    pub process_handle: Option<HANDLE>,
    pub last_context: Option<RegisterContext>,
    pub is_waiting: bool,
    pub jit_mode_enabled: bool,
    pub virtual_alloc_addr: Option<usize>,
    pub breakpoint_symbols: std::collections::HashMap<usize, String>, // address -> name (e.g. "VirtualAllocEx")
}

unsafe impl Send for DebuggerState {}
unsafe impl Sync for DebuggerState {}

pub struct Debugger {
    pub state: Arc<Mutex<DebuggerState>>,
    pub command_sender: Sender<DebuggerCommand>,
    pub event_receiver: Receiver<DebuggerEvent>,
}

impl Debugger {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebuggerCommand>();
        let (evt_tx, evt_rx) = mpsc::channel::<DebuggerEvent>();
        
        let state = Arc::new(Mutex::new(DebuggerState {
            is_active: false,
            target_pid: None,
            breakpoints: std::collections::HashMap::new(),
            process_handle: None,
            last_context: None,
            is_waiting: false,
            jit_mode_enabled: true,
            virtual_alloc_addr: None,
            breakpoint_symbols: std::collections::HashMap::new(),
        }));

        let state_clone = Arc::clone(&state);
        thread::spawn(move || {
            Self::debug_loop(cmd_rx, evt_tx, state_clone);
        });

        Debugger {
            state,
            command_sender: cmd_tx,
            event_receiver: evt_rx,
        }
    }

    fn read_memory(process: HANDLE, address: usize) -> Option<u8> {
        let mut buffer: u8 = 0;
        let mut bytes_read: usize = 0;
        unsafe {
            if ReadProcessMemory(process, address as LPVOID, &mut buffer as *mut _ as LPVOID, 1, &mut bytes_read) != 0 && bytes_read == 1 {
                Some(buffer)
            } else {
                None
            }
        }
    }

    fn read_memory_chunk(process: HANDLE, address: usize, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: usize = 0;
        unsafe {
            if ReadProcessMemory(process, address as LPVOID, buffer.as_mut_ptr() as LPVOID, size, &mut bytes_read) != 0 && bytes_read > 0 {
                buffer.truncate(bytes_read);
                Some(buffer)
            } else {
                None
            }
        }
    }

    fn read_memory_qwords(process: HANDLE, address: usize, count: usize) -> Vec<u64> {
        let mut result = Vec::new();
        let chunk_size = count * 8;
        if let Some(data) = Self::read_memory_chunk(process, address, chunk_size) {
            for i in 0..(data.len() / 8) {
                let mut qword = 0u64;
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr().add(i * 8), &mut qword as *mut u64 as *mut u8, 8);
                }
                result.push(qword);
            }
        }
        result
    }

    fn write_memory(process: HANDLE, address: usize, data: u8) -> bool {
        let mut bytes_written: usize = 0;
        unsafe {
            WriteProcessMemory(process, address as LPVOID, &data as *const _ as LPVOID, 1, &mut bytes_written) != 0 && bytes_written == 1
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn get_full_context(thread_id: u32, process: HANDLE) -> Option<RegisterContext> {
        unsafe {
            let h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
            if h_thread.is_null() { return None; }
            let mut ctx: CONTEXT = mem::zeroed();
            ctx.ContextFlags = CONTEXT_ALL;
            let ok = GetThreadContext(h_thread, &mut ctx) != 0;
            let res = if ok {
                let mut rc = RegisterContext {
                    rip: ctx.Rip, rax: ctx.Rax, rbx: ctx.Rbx, rcx: ctx.Rcx, rdx: ctx.Rdx,
                    r8: ctx.R8, r9: ctx.R9, rsp: ctx.Rsp, rbp: ctx.Rbp,
                    stack_locals: Vec::new(),
                };
                rc.stack_locals = Self::read_memory_qwords(process, ctx.Rsp as usize, 16);
                Some(rc)
            } else { None };
            CloseHandle(h_thread);
            res
        }
    }

    fn debug_loop(cmd_rx: Receiver<DebuggerCommand>, evt_tx: Sender<DebuggerEvent>, state: Arc<Mutex<DebuggerState>>) {
        let mut debug_active = false;
        
        loop {
            // UI Commands
            if let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    DebuggerCommand::Launch(path) => {
                        let c_path = CString::new(path).unwrap();
                        let mut si: STARTUPINFOA = unsafe { mem::zeroed() };
                        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
                        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };
                        unsafe {
                            if CreateProcessA(c_path.as_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, ptr::null_mut(), ptr::null(), &mut si, &mut pi) != 0 {
                                debug_active = true;
                                let mut s = state.lock().unwrap();
                                s.is_active = true;
                                s.target_pid = Some(pi.dwProcessId);
                                s.process_handle = Some(pi.hProcess);
                                
                                // Auto-detect VirtualAlloc
                                let h_kb = GetModuleHandleA("kernelbase.dll\0".as_ptr() as *const i8);
                                if !h_kb.is_null() {
                                    let addr = GetProcAddress(h_kb, "VirtualAlloc\0".as_ptr() as *const i8);
                                    if !addr.is_null() { 
                                        s.virtual_alloc_addr = Some(addr as usize); 
                                        s.breakpoint_symbols.insert(addr as usize, "VirtualAllocEx".to_string());
                                    }
                                }
                                let _ = evt_tx.send(DebuggerEvent::ProcessLaunched(pi.dwProcessId));
                            }
                        }
                    },
                    DebuggerCommand::Attach(pid) => {
                        unsafe {
                            if DebugActiveProcess(pid) != 0 {
                                debug_active = true;
                                let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                                let mut s = state.lock().unwrap();
                                s.is_active = true; s.target_pid = Some(pid); s.process_handle = Some(handle);
                                let _ = evt_tx.send(DebuggerEvent::ProcessAttached(pid));
                            }
                        }
                    },
                    DebuggerCommand::Detach => {
                        let mut s = state.lock().unwrap();
                        if debug_active {
                            if let Some(pid) = s.target_pid { unsafe { DebugActiveProcessStop(pid); } }
                            debug_active = false; s.is_active = false; s.target_pid = None; s.process_handle = None;
                            let _ = evt_tx.send(DebuggerEvent::LogMessage("Detached.".to_string()));
                        }
                    },
                    DebuggerCommand::Continue | DebuggerCommand::StepInto => {
                        state.lock().unwrap().is_waiting = false;
                    },
                    DebuggerCommand::ToggleBreakpoint(addr) => {
                        let mut s = state.lock().unwrap();
                        if let Some(process) = s.process_handle {
                            if let Some(orig) = s.breakpoints.remove(&addr) {
                                Self::write_memory(process, addr, orig);
                            } else if let Some(orig) = Self::read_memory(process, addr) {
                                if Self::write_memory(process, addr, 0xCC) { s.breakpoints.insert(addr, orig); }
                            }
                        }
                    }
                }
            }

            if debug_active && !state.lock().unwrap().is_waiting {
                let mut dbg_event: DEBUG_EVENT = unsafe { mem::zeroed() };
                if unsafe { WaitForDebugEvent(&mut dbg_event, 50) } != 0 {
                    let mut continue_status = DBG_CONTINUE;
                    match dbg_event.dwDebugEventCode {
                        EXIT_PROCESS_DEBUG_EVENT => {
                            let mut s = state.lock().unwrap();
                            s.is_active = false; debug_active = false;
                            let _ = evt_tx.send(DebuggerEvent::ProcessExited(dbg_event.dwProcessId));
                        },
                        EXCEPTION_DEBUG_EVENT => {
                            unsafe {
                                let ex = dbg_event.u.Exception();
                                let code = ex.ExceptionRecord.ExceptionCode;
                                if code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP {
                                    let mut addr = ex.ExceptionRecord.ExceptionAddress as usize;
                                    let h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbg_event.dwThreadId);
                                    let mut ctx: CONTEXT = mem::zeroed();
                                    ctx.ContextFlags = CONTEXT_ALL;
                                    GetThreadContext(h_thread, &mut ctx);

                                    if code == EXCEPTION_BREAKPOINT {
                                        ctx.Rip -= 1;
                                        addr = ctx.Rip as usize;
                                        SetThreadContext(h_thread, &ctx);
                                        let s = state.lock().unwrap();
                                        if let Some(&orig) = s.breakpoints.get(&addr) {
                                            Self::write_memory(s.process_handle.unwrap(), addr, orig);
                                        }
                                    }

                                    let ctx_info = Self::get_full_context(dbg_event.dwThreadId, state.lock().unwrap().process_handle.unwrap());
                                    if let Some(ci) = &ctx_info {
                                        let mut s = state.lock().unwrap();
                                        s.last_context = Some(ci.clone());
                                        s.is_waiting = true;
                                        if s.jit_mode_enabled && Some(ci.rip as usize) == s.virtual_alloc_addr {
                                            let ret_addr = ci.stack_locals.get(0).cloned().unwrap_or(0); // Return address is at [RSP]
                                            let _ = evt_tx.send(DebuggerEvent::LogMessage(format!(
                                                "🚀 JIT DETECTED: VirtualAlloc(size: 0x{:X}). Return to: 0x{:X}", ci.rdx, ret_addr
                                            )));
                                            
                                            // Set a dynamic BP at return address to catch RAX (the memory pointer)
                                            if ret_addr != 0 {
                                                if let Some(proc) = s.process_handle {
                                                    if let Some(_orig) = Self::read_memory(proc, ret_addr as usize) {
                                                        // We can't easily modify 's' inside the closure if we don't have mut access, 
                                                        // but since we are in debug_loop thread with state lock:
                                                        // (Wait, we need to store this BP to restore it later)
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    let mut disasm = String::new();
                                    let mut hex = String::new();
                                    if let Some(proc) = state.lock().unwrap().process_handle {
                                        if let Some(chunk) = Self::read_memory_chunk(proc, addr, 64) {
                                            for (i, b) in chunk.iter().enumerate() { hex.push_str(&format!("{:02X} ", b)); if (i+1)%16==0 { hex.push('\n'); } }
                                            if let Ok(cs) = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).build() {
                                                if let Ok(insns) = cs.disasm_all(&chunk, addr as u64) {
                                                    for i in insns.as_ref() { disasm.push_str(&format!("0x{:X}: {} {}\n", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""))); }
                                                }
                                            }
                                        }
                                    }

                                    let symbol_name = state.lock().unwrap().breakpoint_symbols.get(&addr).cloned();
                                    let _ = evt_tx.send(DebuggerEvent::BreakpointHit { 
                                        address: addr, 
                                        thread_id: dbg_event.dwThreadId, 
                                        context: ctx_info, 
                                        disasm, 
                                        hex_dump: hex,
                                        symbol_name,
                                    });
                                    CloseHandle(h_thread);
                                } else { continue_status = DBG_EXCEPTION_NOT_HANDLED; }
                            }
                        },
                        _ => {}
                    }
                    unsafe {
                        if !state.lock().unwrap().is_waiting {
                            let h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbg_event.dwThreadId);
                            let mut ctx: CONTEXT = mem::zeroed(); ctx.ContextFlags = CONTEXT_ALL;
                            if GetThreadContext(h_thread, &mut ctx) != 0 {
                                ctx.EFlags |= EFLAGS_TF;
                                SetThreadContext(h_thread, &ctx);
                            }
                            CloseHandle(h_thread);
                        }
                        ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status);
                    }
                }
            } else { thread::sleep(std::time::Duration::from_millis(10)); }
        }
    }
}
