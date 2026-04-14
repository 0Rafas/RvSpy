use base64::{Engine as _, engine::general_purpose};

pub enum DecryptionMethod {
    Base64,
    XorSingleByte(u8),
}

pub struct DecryptedString {
    pub original: String,
    pub decrypted: String,
    pub method: DecryptionMethod,
}

/// Checks if a string contains mostly printable English-like characters after decryption.
fn is_printable_ascii(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    
    let mut printable_count = 0;
    for &b in data {
        // Broad printable ASCII check (space to tilde), also allows newlines and tabs
        if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
            printable_count += 1;
        }
    }
    
    // If the ratio of printable characters is very high (>90%), we assume it's valid text.
    let ratio = printable_count as f32 / data.len() as f32;
    ratio >= 0.90
}

/// Attempts to auto-decrypt a list of extracted strings using heuristics
pub fn run_heuristics_on_strings(strings: &[String]) -> Vec<DecryptedString> {
    let mut results = Vec::new();
    
    for s in strings {
        // Strip out the (UTF-16) tag if present
        let clean_s = if s.starts_with("(UTF-16) ") {
            &s[9..]
        } else {
            s
        };
        
        // 1. Base64 Heuristic Check
        // Usually obfuscated base64 strings have a minimum length to be interesting
        if clean_s.len() > 10 && clean_s.len() % 4 == 0 {
            // Check if string characters are roughly valid b64
            let is_valid_b64_chars = clean_s.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
            });
            
            if is_valid_b64_chars {
                if let Ok(decoded) = general_purpose::STANDARD.decode(clean_s) {
                    if is_printable_ascii(&decoded) {
                        if let Ok(utf8_str) = String::from_utf8(decoded.clone()) {
                            results.push(DecryptedString {
                                original: s.clone(),
                                decrypted: utf8_str,
                                method: DecryptionMethod::Base64,
                            });
                        }
                    }
                }
            }
        }
        
        // 2. XOR Single-Byte Heuristic Bruteforce
        if clean_s.len() > 8 && clean_s.len() < 2048 {
            for key in 1u8..=255u8 {
                let mut printable_count = 0;
                for b in clean_s.bytes() {
                    let xb = b ^ key;
                    if (xb >= 32 && xb <= 126) || xb == 9 || xb == 10 || xb == 13 {
                        printable_count += 1;
                    }
                }
                
                let ratio = printable_count as f32 / clean_s.len() as f32;
                if ratio >= 0.90 {
                    let xored_bytes: Vec<u8> = clean_s.bytes().map(|b| b ^ key).collect();
                    if let Ok(utf8_str) = String::from_utf8(xored_bytes) {
                        // Skip if the output is the same as input
                        if utf8_str != *clean_s {
                            results.push(DecryptedString {
                                original: s.clone(),
                                decrypted: utf8_str,
                                method: DecryptionMethod::XorSingleByte(key),
                            });
                        }
                    }
                }
            }
        }
    }
    
    results
}
