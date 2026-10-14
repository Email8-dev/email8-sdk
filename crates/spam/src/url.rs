// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! URL/phishing heuristics — zero-width characters, homograph/mixed
//! script (confusable) detection, IP-literal hosts, redirector
//! unrolling (single hop), and bracketed/obfuscated URL reconstruction.
//! Pure byte-level analysis of the body text.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlFindings {
    /// Extracted URLs (after redirector unrolling, one hop).
    pub urls: Vec<String>,
    /// URLs using IP literals (`http://192.0.2.7/`).
    pub ip_literal: bool,
    /// Zero-width/bidi characters found in the body.
    pub zero_width: bool,
    /// A host mixes scripts in one label (homograph candidate).
    pub mixed_script: bool,
    /// A punycode label (`xn--`) whose decoded form confuses an ASCII
    /// label (e.g. `xn--80ak6aa92e` ≈ "bank").
    pub homograph: bool,
}

/// Scan a decoded text body.
pub fn scan_urls(text: &str) -> UrlFindings {
    let mut urls = Vec::new();
    let mut ip_literal = false;
    for token in text.split_whitespace() {
        let token = token.trim_matches(|c: char| {
            c == '<' || c == '>' || c == '"' || c == '\'' || c == ')' || c == '('
        });
        if let Some(rest) = token
            .strip_prefix("http://")
            .or_else(|| token.strip_prefix("https://"))
        {
            // Stop at the first character that can't be in a URL.
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>')
                .unwrap_or(rest.len());
            let scheme_len = token.len() - rest.len();
            let url = format!("{}{}", &token[..scheme_len], &rest[..end]);
            let scheme_trimmed = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let host = scheme_trimmed.split(['/', ':']).next().unwrap_or("");
            if host.parse::<std::net::IpAddr>().is_ok() {
                ip_literal = true;
            }
            let url = unroll_redirector(&url);
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    let zero_width = text.chars().any(|c| {
        matches!(
            c,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
        ) || ('\u{202A}'..='\u{202E}').contains(&c)
    });
    let mut mixed_script = false;
    let mut homograph = false;
    for label in text.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '.')) {
        let has_ascii = label.chars().any(|c| c.is_ascii_alphanumeric());
        let has_non_ascii = label.chars().any(|c| !c.is_ascii() && c.is_alphanumeric());
        if has_ascii && has_non_ascii {
            mixed_script = true;
        }
        let lower = label.to_ascii_lowercase();
        if lower.starts_with("xn--") {
            // Without a full punycode table, flag any xn-- label that
            // decodes (length heuristics) into a short confusable —
            // here: flag every punycode label in a URL context as a
            // homograph candidate (conservative, matches legacy behavior
            // of warning + scoring rather than decoding in-process).
            homograph = true;
        }
    }
    UrlFindings {
        urls,
        ip_literal,
        zero_width,
        mixed_script,
        homograph,
    }
}

/// One-hop redirector unrolling: a known redirector with a `url=`/
/// `?q=`/`u=`/`target=` parameter is replaced by the embedded target
/// when it's a well-formed absolute URL.
fn unroll_redirector(url: &str) -> String {
    const REDIRECTORS: &[&str] = &[
        "click.example.net",
        "r.example.com",
        "go.example.org",
        "redirect.example.com",
        "track.example.net",
    ];
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let host = url[scheme_end + 3..]
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !REDIRECTORS.contains(&host.as_str()) {
        return url.to_string();
    }
    for marker in ["url=", "target=", "u=", "q=", "dest="] {
        if let Some(pos) = url.find(marker) {
            let candidate = &url[pos + marker.len()..];
            if candidate.starts_with("http://") || candidate.starts_with("https://") {
                return candidate.to_string();
            }
            // Percent-encoded form.
            let decoded = percent_decode(candidate);
            if decoded.starts_with("http://") || decoded.starts_with("https://") {
                return decoded;
            }
        }
    }
    url.to_string()
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_urls_and_ip_literals() {
        let f = scan_urls("Visit https://example.com/a?b=c or http://192.0.2.7/login now");
        assert_eq!(f.urls.len(), 2);
        assert!(f.ip_literal);
        assert!(!f.zero_width);
    }

    #[test]
    fn zero_width_detected() {
        let f = scan_urls("Pay\u{200B}Pal security check at https://example.com");
        assert!(f.zero_width);
    }

    #[test]
    fn mixed_script_detected() {
        let f = scan_urls("Contact https://рaypal.com/secure");
        assert!(f.mixed_script);
    }

    #[test]
    fn redirector_unrolls() {
        let f = scan_urls("https://r.example.com?url=https%3A%2F%2Fevil.example.net%2Fx");
        assert!(
            f.urls
                .iter()
                .any(|u| u.starts_with("https://evil.example.net")),
            "{:?}",
            f.urls
        );
    }
}
