// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! DKIM (RFC 6376) — sign + verify with relaxed/simple canonicalization,
//! rsa-sha256 and ed25519-sha256, header chaining, `l=` body length,
//! `t=` timestamps. Verification is incremental like the legacy
//! implementation: each signature verifies independently; weak/failed
//! signatures are reported (strip policy belongs to the caller).

use base64::Engine;
use sha2::{Digest, Sha256};

/// A parsed DKIM-Signature header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature {
    pub version: String,
    pub algorithm: String, // rsa-sha256 | ed25519-sha256
    pub domain: String,     // d=
    pub selector: String,   // s=
    pub headers: Vec<String>, // h= (lowercased, in order)
    pub body_hash: String, // bh= (base64)
    pub signature: String, // b= (base64)
    pub identity: Option<String>, // i=
    pub body_length: Option<u64>, // l=
    pub timestamp: Option<i64>,   // t=
    pub expiry: Option<i64>,     // x=
    pub copied_headers: Option<String>, // z=
    /// Parsed c= pair (header, body) canonicalization modes.
    pub canon: (CanonMode, CanonMode),
}

/// Canonicalization mode pair `(header, body)` from c=.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonMode {
    Simple,
    Relaxed,
}

impl CanonMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "simple" => Some(CanonMode::Simple),
            "relaxed" => Some(CanonMode::Relaxed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DkimVerifyOutcome {
    /// One outcome per DKIM-Signature header, in message order.
    pub results: Vec<SingleDkim>,
}

/// Result for a single signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleDkim {
    pub domain: String,
    pub selector: String,
    pub identity: Option<String>,
    pub result: DkimStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimStatus {
    Pass,
    Fail(String),
    TempError(String),
    PermError(String),
    /// No key published (NORECORD) — the caller strips and reports.
    NoKey,
}

impl DkimStatus {
    pub fn token(&self) -> &'static str {
        match self {
            DkimStatus::Pass => "pass",
            DkimStatus::Fail(_) => "fail",
            DkimStatus::TempError(_) => "temperror",
            DkimStatus::PermError(_) => "permerror",
            DkimStatus::NoKey => "none",
        }
    }
}

// ── Canonicalization ─────────────────────────────────────────────────────

fn unfold(value: &str) -> String {
    // CRLF continuations become single spaces (preserve the semantic).
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
                if out.ends_with(' ') {
                    // already space-separated
                } else {
                    out.push(' ');
                }
            } else {
                out.push('\r');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2).
fn canon_header_relaxed(name: &str, value: &str) -> String {
    let mut value = unfold(value.trim());
    // Collapse internal WSP sequences.
    let mut collapsed = String::with_capacity(value.len());
    let mut last_ws = false;
    for ch in value.chars() {
        if ch == ' ' || ch == '\t' {
            if !last_ws {
                collapsed.push(' ');
            }
            last_ws = true;
        } else {
            collapsed.push(ch);
            last_ws = false;
        }
    }
    value = collapsed.trim_end().to_string();
    format!("{}:{}", name.to_ascii_lowercase(), value)
}

/// Simple header canonicalization (§3.4.1) — name + unfolded value, CRLF.
fn canon_header_simple(name: &str, value: &str) -> String {
    format!("{}:{}\r\n", name, unfold(value))
}

fn canon_body(body: &[u8], mode: CanonMode, length: Option<u64>) -> Vec<u8> {
    let body = match length {
        Some(l) => &body[..body.len().min(l as usize)],
        None => body,
    };
    match mode {
        CanonMode::Simple => {
            // Strip trailing empty lines; ensure CRLF ending.
            let text = String::from_utf8_lossy(body);
            let mut s = text.trim_end_matches('\n').trim_end_matches('\r').to_string();
            s.push_str("\r\n");
            s.into_bytes()
        }
        CanonMode::Relaxed => {
            let text = String::from_utf8_lossy(body);
            let mut s = String::with_capacity(text.len());
            let mut last_ws = false;
            for ch in text.chars() {
                if ch == ' ' || ch == '\t' {
                    if !last_ws {
                        s.push(' ');
                    }
                    last_ws = true;
                } else {
                    s.push(ch);
                    last_ws = false;
                }
            }
            // Strip WSP at line ends and remove trailing empty lines
            // (§3.4.3); interior leading WSP is preserved.
            let mut lines: Vec<String> = s
                .split("\r\n")
                .map(|l| l.trim_end_matches(' ').to_string())
                .collect();
            while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                lines.pop();
            }
            if lines.is_empty() {
                return b"\r\n".to_vec();
            }
            format!("{}\r\n", lines.join("\r\n")).into_bytes()
        }
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse a DKIM-Signature header value into its fields.
pub fn parse_signature(value: &str) -> Option<DkimSignature> {
    let mut sig = DkimSignature {
        version: String::new(),
        algorithm: String::new(),
        domain: String::new(),
        selector: String::new(),
        headers: Vec::new(),
        body_hash: String::new(),
        signature: String::new(),
        identity: None,
        body_length: None,
        timestamp: None,
        expiry: None,
        copied_headers: None,
        canon: (CanonMode::Simple, CanonMode::Simple),
    };
    let mut canon = (CanonMode::Simple, CanonMode::Simple);
    for tag in unfold(value).split(';') {
        let (k, v) = tag.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "v" => sig.version = v.to_string(),
            "a" => sig.algorithm = v.to_ascii_lowercase(),
            "d" => sig.domain = v.to_ascii_lowercase(),
            "s" => sig.selector = v.to_string(),
            "h" => sig.headers = v
                .split(':')
                .map(|h| h.trim().to_ascii_lowercase())
                .collect(),
            "bh" => sig.body_hash = v.to_string(),
            "b" => sig.signature = v.replace([' ', '\t'], ""),
            "c" => {
                let mut it = v.splitn(2, '/');
                canon.0 = CanonMode::parse(it.next()?).unwrap_or(CanonMode::Simple);
                canon.1 = it.next().and_then(CanonMode::parse).unwrap_or(canon.0);
            }
            "i" => sig.identity = Some(v.to_string()),
            "l" => sig.body_length = v.parse().ok(),
            "t" => sig.timestamp = v.parse().ok(),
            "x" => sig.expiry = v.parse().ok(),
            "z" => sig.copied_headers = Some(v.to_string()),
            _ => {}
        }
    }
    if sig.version != "1" || sig.algorithm.is_empty() || sig.domain.is_empty()
        || sig.selector.is_empty() || sig.headers.is_empty() || sig.signature.is_empty()
    {
        return None;
    }
    sig.canon = canon;
    Some(sig)
}

// ── Verification ─────────────────────────────────────────────────────────

/// Verify every DKIM-Signature header in the raw message.
pub async fn dkim_verify(dns: &dyn crate::DnsTxt, raw: &[u8]) -> DkimVerifyOutcome {
    let headers = extract_headers(raw);
    let body_offset = find_body_offset(raw);
    let body = &raw[body_offset.min(raw.len())..];
    let mut results = Vec::new();
    for (name, value) in &headers {
        if !name.eq_ignore_ascii_case("dkim-signature") {
            continue;
        }
        let Some(sig) = parse_signature(value) else {
            results.push(SingleDkim {
                domain: "?".into(),
                selector: String::new(),
                identity: None,
                result: DkimStatus::PermError("unparseable signature".into()),
            });
            continue;
        };
        let result = verify_one(dns, &headers, body, &sig).await;
        results.push(SingleDkim {
            domain: sig.domain.clone(),
            selector: sig.selector.clone(),
            identity: sig.identity.clone(),
            result,
        });
    }
    DkimVerifyOutcome { results }
}

async fn verify_one(
    dns: &dyn crate::DnsTxt,
    headers: &[(String, String)],
    body: &[u8],
    sig: &DkimSignature,
) -> DkimStatus {
    // x= expiry check.
    if let Some(x) = sig.expiry {
        let now = chrono::Utc::now().timestamp();
        if x < now {
            return DkimStatus::PermError("signature expired (x=)".into());
        }
    }
    // Body hash.
    let (hcanon, bcanon) = sig.canon;
    let canon_body = canon_body(body, bcanon, sig.body_length);
    let body_hash = Sha256::digest(&canon_body);
    let expected = base64::engine::general_purpose::STANDARD.encode(body_hash);
    if !constant_time_eq(&expected, &sig.body_hash) {
        return DkimStatus::Fail("body hash mismatch".into());
    }
    // Fetch the key.
    let key_name = format!("{}._domainkey.{}", sig.selector, sig.domain);
    let Ok(records) = dns.lookup_txt(&key_name).await else {
        return DkimStatus::TempError("key lookup failed".into());
    };
    let Some(record) = records.first() else {
        return DkimStatus::NoKey;
    };
    let (key_type, public_key) = match parse_key_record(record) {
        Some(kv) => kv,
        None => return DkimStatus::PermError("unparseable key record".into()),
    };
    // Build the signed data: canonicalized h= headers + the (b-stripped)
    // DKIM-Signature header itself. RFC 6376 §3.4.2 — each canonicalized
    // header ends with CRLF.
    let data = build_signed_data(headers, sig, hcanon);
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&sig.signature) {
        Ok(b) => b,
        Err(_) => return DkimStatus::PermError("b= is not base64".into()),
    };
    let verified = match (key_type.as_str(), sig.algorithm.as_str()) {
        ("rsa", "rsa-sha256") => rsa_verify(&public_key, &data, &sig_bytes),
        ("ed25519", "ed25519-sha256") => {
            let pk = public_key
                .as_slice()
                .try_into()
                .ok()
                .and_then(|arr: &[u8; 32]| ed25519_dalek::VerifyingKey::from_bytes(arr).ok());
            let Some(pk) = pk else {
                return DkimStatus::PermError("bad ed25519 key".into());
            };
            use ed25519_dalek::Signature;
            let Ok(s) = Signature::from_slice(&sig_bytes) else {
                return DkimStatus::PermError("bad ed25519 signature".into());
            };
            use ed25519_dalek::Verifier;
            pk.verify(&data, &s).is_ok()
        }
        _ => return DkimStatus::PermError("algorithm/key type mismatch".into()),
    };
    if verified {
        DkimStatus::Pass
    } else {
        DkimStatus::Fail("signature verification failed".into())
    }
}

fn rsa_verify(public_key: &[u8], data: &[u8], sig: &[u8]) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(public_key) else {
        return false;
    };
    let hashed = Sha256::digest(data);
    key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, sig).is_ok()
}

fn parse_key_record(record: &str) -> Option<(String, Vec<u8>)> {
    let mut key_type = String::new();
    let mut key_b64 = String::new();
    for tag in unfold(record).split(';') {
        let (k, v) = tag.split_once('=')?;
        match k.trim().to_ascii_lowercase().as_str() {
            "k" => key_type = v.trim().to_ascii_lowercase(),
            "p" => key_b64 = v.trim().replace([' ', '\t'], ""),
            _ => {}
        }
    }
    if key_b64.is_empty() {
        return None;
    }
    // Empty p= means the key is revoked.
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&key_b64) else {
        return None;
    };
    if bytes.is_empty() {
        return None;
    }
    if key_type.is_empty() {
        key_type = "rsa".into();
    }
    Some((key_type, bytes))
}

fn build_signed_data(
    headers: &[(String, String)],
    sig: &DkimSignature,
    mode: CanonMode,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(1024);
    // Each h= entry consumes one occurrence of that header, bottom-up
    // per RFC 6376 §3.7 (repeated names select from the bottom).
    let mut consumed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for name in &sig.headers {
        let want = consumed.entry(name.clone()).or_insert(0);
        // Find the *want*-th occurrence from the bottom.
        let matches: Vec<&(String, String)> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .collect();
        let idx = matches.len().saturating_sub(1).saturating_sub(*want);
        if let Some((n, v)) = matches.get(idx) {
            match mode {
                CanonMode::Relaxed => {
                    data.extend_from_slice(canon_header_relaxed(n, v).as_bytes());
                    data.extend_from_slice(b"\r\n");
                }
                CanonMode::Simple => data.extend_from_slice(canon_header_simple(n, v).as_bytes()),
            }
            *want += 1;
        }
    }
    // The DKIM-Signature header itself, canonicalized, with b= value
    // stripped (the tag value removed, the tag kept). §3.7: it is the
    // last header in the hash input and ends WITHOUT the trailing CRLF.
    let sig_header = headers
        .iter()
        .rev()
        .find(|(n, _)| n.eq_ignore_ascii_case("dkim-signature"));
    if let Some((n, v)) = sig_header {
        let stripped = strip_b_tag(v);
        match mode {
            CanonMode::Relaxed => data.extend_from_slice(canon_header_relaxed(n, &stripped).as_bytes()),
            CanonMode::Simple => {
                // Simple canon strips the trailing CRLF for the b= hash.
                let c = canon_header_simple(n, &stripped);
                let c = c.trim_end_matches('\r').trim_end_matches('\n');
                data.extend_from_slice(c.as_bytes());
            }
        }
    }
    data
}

fn strip_b_tag(value: &str) -> String {
    // Remove everything between "b=" and the next ";" or end.
    let unfolded = unfold(value);
    let lower = unfolded.to_ascii_lowercase();
    let mut out = String::with_capacity(unfolded.len());
    let mut i = 0usize;
    let bytes = unfolded.as_bytes();
    while i < bytes.len() {
        if lower[i..].starts_with("b=") && !lower[..i].ends_with("h=")
            && !lower[..i].ends_with("bh=")
        {
            // Skip the tag; but careful: "bh=" also matches "b=" at the
            // position of 'h'. Guard: the char before must not be 'h'.
            let prev_is_h = i > 0 && lower.as_bytes()[i - 1] == b'h';
            if !prev_is_h {
                out.push_str("b=");
                i += 2;
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn extract_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let head_end = text.find("\r\n\r\n").map(|p| p + 4).unwrap_or(text.len());
    let head = &text[..head_end];
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.split_inclusive('\n') {
        let line = line.trim_end_matches('\r').trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            headers.push((n.trim().to_string(), v.trim().to_string()));
        }
    }
    headers
}

fn find_body_offset(raw: &[u8]) -> usize {
    memchr::memmem::find(raw, b"\r\n\r\n").map(|p| p + 4).unwrap_or(raw.len())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    // Base64 of a SHA-256 — timing side channels are not meaningful here,
    // but compare in constant time anyway.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Signing ───────────────────────────────────────────────────────────────

/// Signing key material resolved from a secret reference.
#[derive(Debug, Clone)]
pub enum DkimKey {
    Rsa2048(Vec<u8>), // PEM private key
    Ed25519(Vec<u8>), // 32-byte seed or PKCS8
}

/// Sign a message, inserting the DKIM-Signature header text (including
/// trailing CRLF) at the front of the header block.
///
/// `headers_to_sign` follows legacy `sign_chained`: Received, AR, and
/// the standard set, in order. Returns the header block to prepend.
pub fn dkim_sign(
    key: &DkimKey,
    domain: &str,
    selector: &str,
    headers_to_sign: &[&str],
    raw: &[u8],
) -> Result<String, String> {
    let (algorithm, _key_tag) = match key {
        DkimKey::Rsa2048(_) => ("rsa-sha256", "rsa"),
        DkimKey::Ed25519(_) => ("ed25519-sha256", "ed25519"),
    };
    let headers = extract_headers(raw);
    let body_offset = find_body_offset(raw);
    let body = &raw[body_offset.min(raw.len())..];
    // relaxed/relaxed canonicalization (the legacy default).
    let canon_body = canon_body(body, CanonMode::Relaxed, None);
    let body_hash = Sha256::digest(&canon_body);
    let bh = base64::engine::general_purpose::STANDARD.encode(body_hash);
    // Ensure the required headers are covered (RFC 6376 §5.4: from is
    // MANDATORY).
    let mut signed: Vec<String> = headers_to_sign
        .iter()
        .filter(|h| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(h)))
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if !signed.iter().any(|h| h == "from") {
        signed.push("from".into());
    }
    // Timestamp.
    let now = chrono::Utc::now().timestamp();
    let h_list = signed.join(":");
    let mut sig_header = format!(
        "DKIM-Signature: v=1; a={algorithm}; c=relaxed/relaxed; d={domain}; s={selector}; t={now}; h={h_list}; bh={bh}; b="
    );
    // Build the signed data over the selected headers (same layout as
    // verification: each header + CRLF; the signature header last,
    // without trailing CRLF).
    let mut data = Vec::with_capacity(1024);
    let mut consumed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for name in &signed {
        let want = consumed.entry(name.clone()).or_insert(0);
        let matches: Vec<&(String, String)> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .collect();
        let idx = matches.len().saturating_sub(1).saturating_sub(*want);
        if let Some((n, v)) = matches.get(idx) {
            data.extend_from_slice(canon_header_relaxed(n, v).as_bytes());
            data.extend_from_slice(b"\r\n");
            *want += 1;
        }
    }
    // The new DKIM-Signature header participates with an empty b= —
    // canonicalized, no trailing CRLF (RFC 6376 §3.7).
    let pseudo = strip_b_tag(&sig_header);
    let canon_self = canon_header_relaxed("DKIM-Signature", pseudo.split_once(':').unwrap().1.trim());
    data.extend_from_slice(canon_self.as_bytes());
    // Compute the signature.
    let signature_b64 = match key {
        DkimKey::Rsa2048(pem) => {
            use rsa::pkcs8::DecodePrivateKey;
            let sk = rsa::RsaPrivateKey::from_pkcs8_pem(
                String::from_utf8(pem.to_vec()).map_err(|e| e.to_string())?.as_str(),
            )
            .map_err(|e| format!("bad rsa key: {e}"))?;
            let hashed = Sha256::digest(&data);
            let sig = sk
                .sign_with_rng(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed)
                .map_err(|e| e.to_string())?;
            base64::engine::general_purpose::STANDARD.encode(sig)
        }
        DkimKey::Ed25519(bytes) => {
            let sk: ed25519_dalek::SigningKey = if bytes.len() == 32 {
                let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    return Err("bad ed25519 seed".into());
                };
                ed25519_dalek::SigningKey::from_bytes(&seed)
            } else {
                use ed25519_dalek::pkcs8::DecodePrivateKey;
                ed25519_dalek::SigningKey::from_pkcs8_pem(
                    String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())?.as_str(),
                )
                .map_err(|e| format!("bad ed25519 key: {e}"))?
            };
            use ed25519_dalek::Signer;
            let sig = sk.sign(&data);
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        }
    };
    sig_header.push_str(&signature_b64);
    Ok(format!("{sig_header}\r\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"From: Alice <alice@football.example.com>\r\nTo: bob@example.net\r\nSubject: Game today?\r\nDate: Sat, 07 Feb 2026 10:00:00 +0000\r\nMessage-ID: <q1@football.example.com>\r\n\r\nHI!\r\n\r\n";

    #[tokio::test]
    async fn sign_then_verify_roundtrip_ed25519() {
        // ed25519 roundtrip is self-contained (no DNS needed beyond key
        // fetch which we stub).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let public = sk.verifying_key().to_bytes();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public);
        let dns = crate::FnDnsTxt(|name: &str| {
            assert!(name.starts_with("sel._domainkey."));
            Ok(vec![format!("v=DKIM1; k=ed25519; p={pk_b64}")])
        });
        let header = dkim_sign(
            &DkimKey::Ed25519(vec![42u8; 32].to_vec()),
            "football.example.com",
            "sel",
            &["from", "to", "subject"],
            MSG,
        )
        .unwrap();
        let signed = format!("{header}{}", String::from_utf8_lossy(MSG));
        let outcome = dkim_verify(&dns, signed.as_bytes()).await;
        assert_eq!(outcome.results.len(), 1);
        assert_eq!(outcome.results[0].result, DkimStatus::Pass, "{:?}", outcome.results[0]);
    }

    #[test]
    fn body_hash_relaxed_stable() {
        let a = canon_body(b"HI!\r\n\r\n", CanonMode::Relaxed, None);
        let b = canon_body(b"HI!\r\n\r\n\r\n\r\n", CanonMode::Relaxed, None);
        assert_eq!(a, b);
        // Interior WSP runs reduce to single SP (§3.4.3); trailing WSP
        // and empty lines are stripped — leading WSP reduces but stays.
        let c = canon_body(b"  HI!  \r\n", CanonMode::Relaxed, None);
        assert_eq!(c, b" HI!\r\n".to_vec());
        let d = canon_body(b"H \t I !\r\n", CanonMode::Relaxed, None);
        assert_eq!(d, b"H I !\r\n".to_vec());
    }

    #[test]
    fn strip_b_tag_preserves_bh() {
        let v = "v=1; a=rsa-sha256; bh=AAAABBBB; b=CCCCDDDD";
        let stripped = strip_b_tag(v);
        assert!(stripped.contains("bh=AAAABBBB"));
        assert!(!stripped.contains("CCCCDDDD"));
        assert!(stripped.ends_with("b="));
    }
}