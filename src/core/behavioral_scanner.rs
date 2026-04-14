
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    AntiDebug,
    ProcessInjection,
    Persistence,
    Evasion,
    NuitkaSpecific,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSignature {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: Category,
    pub severity: Severity,
    // Rules for matching
    pub static_markers: Vec<String>, // Strings or symbols to look for
    pub api_sequences: Vec<String>,  // Sequence of API calls
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub signature_id: String,
    pub timestamp: std::time::SystemTime,
    pub context: String, // e.g. "Found string 'IsDebuggerPresent' in .text" or "API call 'VirtualAlloc' detected"
    pub severity: Severity,
    pub category: Category,
}

pub struct BehavioralScanner {
    pub signatures: Vec<BehavioralSignature>,
    pub observed_api_calls: Vec<String>,
}

impl BehavioralScanner {
    pub fn new() -> Self {
        let mut signatures = Vec::new();

        // 1. Anti-Debug Signatures
        signatures.push(BehavioralSignature {
            id: "AD_001".to_string(),
            name: "Debugger Presence Check".to_string(),
            description: "Target frequently calls 'IsDebuggerPresent' or 'CheckRemoteDebuggerPresent' to detect tools.".to_string(),
            category: Category::AntiDebug,
            severity: Severity::Medium,
            static_markers: vec!["IsDebuggerPresent".to_string(), "CheckRemoteDebuggerPresent".to_string()],
            api_sequences: vec!["IsDebuggerPresent".to_string()],
        });

        // 2. Process Injection (Classic)
        signatures.push(BehavioralSignature {
            id: "PI_001".to_string(),
            name: "Classic Process Injection".to_string(),
            description: "Sequence of VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread detected.".to_string(),
            category: Category::ProcessInjection,
            severity: Severity::Critical,
            static_markers: vec![],
            api_sequences: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()],
        });

        // 3. Evasion via Timing
        signatures.push(BehavioralSignature {
            id: "EV_001".to_string(),
            name: "Timing-based Evasion".to_string(),
            description: "Frequent calls to 'GetTickCount' or 'QueryPerformanceCounter' used for sandbox timing detection.".to_string(),
            category: Category::Evasion,
            severity: Severity::Low,
            static_markers: vec!["GetTickCount".to_string()],
            api_sequences: vec!["GetTickCount".to_string(), "GetTickCount".to_string()],
        });

        // 4. Persistence Registry
        signatures.push(BehavioralSignature {
            id: "PS_001".to_string(),
            name: "Registry Persistence Attempt".to_string(),
            description: "Application attempts to write to the 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' key.".to_string(),
            category: Category::Persistence,
            severity: Severity::High,
            static_markers: vec!["CurrentVersion\\Run".to_string()],
            api_sequences: vec!["RegSetValueEx".to_string()],
        });

        // 5. Nuitka Obfuscation Detection
        signatures.push(BehavioralSignature {
            id: "NK_001".to_string(),
            name: "Nuitka Internal Marker".to_string(),
            description: "Found Nuitka-specific internal constants suggesting hidden payload execution.".to_string(),
            category: Category::NuitkaSpecific,
            severity: Severity::Medium,
            static_markers: vec!["NUITKA_ENTRY_EXE".to_string(), "__nuitka_binary".to_string()],
            api_sequences: vec![],
        });

        Self {
            signatures,
            observed_api_calls: Vec::new(),
        }
    }

    /// Run a static scan on extracted strings or symbols
    pub fn scan_static(&self, markers: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for sig in &self.signatures {
            for marker in &sig.static_markers {
                if markers.iter().any(|m| m.contains(marker)) {
                    findings.push(Finding {
                        signature_id: sig.id.clone(),
                        timestamp: std::time::SystemTime::now(),
                        context: format!("Static marker '{}' detected in binary/strings.", marker),
                        severity: sig.severity,
                        category: sig.category,
                    });
                }
            }
        }
        findings
    }

    /// Process a new API call and check for sequences
    pub fn update_dynamic(&mut self, api_name: &str) -> Vec<Finding> {
        self.observed_api_calls.push(api_name.to_string());
        
        let mut findings = Vec::new();
        for sig in &self.signatures {
            if sig.api_sequences.is_empty() { continue; }
            
            // Basic sequence matching (look-behind)
            if self.observed_api_calls.len() >= sig.api_sequences.len() {
                let tail = &self.observed_api_calls[self.observed_api_calls.len() - sig.api_sequences.len()..];
                if tail == sig.api_sequences {
                    findings.push(Finding {
                        signature_id: sig.id.clone(),
                        timestamp: std::time::SystemTime::now(),
                        context: format!("Behavioral API sequence detected: {:?}", sig.api_sequences),
                        severity: sig.severity,
                        category: sig.category,
                    });
                }
            }
        }
        findings
    }
}
