pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_ascii = String::new();

    // Simple ASCII extraction
    for &byte in data {
        if byte >= 32 && byte <= 126 {
            current_ascii.push(byte as char);
        } else {
            if current_ascii.len() >= min_length {
                strings.push(current_ascii.clone());
            }
            current_ascii.clear();
        }
    }
    if current_ascii.len() >= min_length {
        strings.push(current_ascii);
    }

    // UTF-16 extraction (Little Endian, which is standard for Windows PE)
    let mut current_utf16 = String::new();
    for chunk in data.chunks_exact(2) {
        let codepoint = u16::from_le_bytes([chunk[0], chunk[1]]);
        if codepoint >= 32 && codepoint <= 126 {
            current_utf16.push(codepoint as u8 as char);
        } else {
            if current_utf16.len() >= min_length {
                strings.push(format!("(UTF-16) {}", current_utf16));
            }
            current_utf16.clear();
        }
    }
    if current_utf16.len() >= min_length {
        strings.push(format!("(UTF-16) {}", current_utf16));
    }

    strings
}

pub fn extract_network_ioc(data: &[u8]) -> Vec<String> {
    let strings = extract_strings(data, 5);
    let mut iocs = Vec::new();

    let ipv4_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let url_regex = regex::Regex::new(r"(?i)\bhttps?://[-a-zA-Z0-9@:%_\+.~#?&/=]+").unwrap();
    let domain_regex = regex::Regex::new(
        r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|org|net|edu|gov|io|co|us|me|dev)\b",
    )
    .unwrap();

    let mut seen = std::collections::HashSet::new();

    for s in strings {
        // Remove the (UTF-16) tag for regex matching if present
        let clean_s = if s.starts_with("(UTF-16) ") {
            &s[9..]
        } else {
            &s
        };

        for mat in ipv4_regex.find_iter(clean_s) {
            let m = format!("[IPv4] {}", mat.as_str());
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
        for mat in url_regex.find_iter(clean_s) {
            let m = format!("[URL] {}", mat.as_str());
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
        for mat in domain_regex.find_iter(clean_s) {
            let m = format!("[Domain] {}", mat.as_str());
            // Filter out false positives
            if mat.as_str().starts_with("127.0.0.1") || mat.as_str().starts_with("0.0.0.0") {
                continue;
            }
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
    }
    iocs
}

pub fn extract_filepath_ioc(data: &[u8]) -> Vec<String> {
    let strings = extract_strings(data, 5);
    let mut iocs = Vec::new();

    let win_path_regex = regex::Regex::new(r"(?i)[a-z]:\\[^:\*\?<>|]+").unwrap();
    let nix_path_regex =
        regex::Regex::new(r"(?i)/(?:usr|etc|bin|opt|var|tmp|home)/[-a-zA-Z0-9_/\.]+").unwrap();
    let reg_regex = regex::Regex::new(
        r"(?i)(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[a-zA-Z0-9_\\]+",
    )
    .unwrap();

    let mut seen = std::collections::HashSet::new();

    for s in strings {
        let clean_s = if s.starts_with("(UTF-16) ") {
            &s[9..]
        } else {
            &s
        };

        for mat in win_path_regex.find_iter(clean_s) {
            let m = format!("[WinPath] {}", mat.as_str());
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
        for mat in nix_path_regex.find_iter(clean_s) {
            let m = format!("[NixPath] {}", mat.as_str());
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
        for mat in reg_regex.find_iter(clean_s) {
            let m = format!("[Registry] {}", mat.as_str());
            if seen.insert(m.clone()) {
                iocs.push(m);
            }
        }
    }
    iocs
}
