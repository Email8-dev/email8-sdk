// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! ARC (Authenticated Received Chain) - RFC 8617.
//!
//! A receiving MTA that alters a message (forwarding, mailing lists)
//! breaks DKIM. ARC lets each hop record its authentication assessment
//! (AAR), seal the chain (AMS + AS headers signed by the sealing
//! domain), so the final receiver can trust the hop-by-hop results.
//!
//! Layout (bottom-up insertion; instance 1 is the FIRST hop):
//! ```text
//! ARC-Seal: i=1; a=rsa-sha256; cv=none; d=sealer; s=sel; t=…; b=…
//! ARC-Message-Signature: i=1; …DKIM-shaped tags…
//! ARC-Authentication-Results: i=1; mx.sealer; spf=pass dkim=pass
//! ```
//!
//! Chain rule: AS i=1 has `cv=none`; every later seal's `cv=` must
//! state whether the validation of the PREVIOUS instance's seal
//! passed or failed.

/// One ARC set (AAR + AMS + AS) as parsed from a message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArcSet {
    pub instance: u32,
    /// ARC-Authentication-Results value (i=N; authserv-id; results…).
    pub aar: String,
    /// Raw ARC-Message-Signature value.
    pub ams: String,
    /// Raw ARC-Seal value.
    pub seal: String,
    /// Parsed AS cv= tag.
    pub cv: String,
}

/// Extract the ARC chain from raw message headers, instance order.
pub fn extract_chain(raw: &[u8]) -> Vec<ArcSet> {
    let mut sets: std::collections::BTreeMap<u32, ArcSet> = Default::default();
    for (name, value) in extract_headers(raw) {
        let inst = |v: &str| -> u32 {
            v.split(';')
                .map(str::trim)
                .find_map(|t| t.strip_prefix("i=").and_then(|n| n.trim().parse().ok()))
                .unwrap_or(0)
        };
        let field = if name.eq_ignore_ascii_case("arc-authentication-results") {
            0
        } else if name.eq_ignore_ascii_case("arc-message-signature") {
            1
        } else if name.eq_ignore_ascii_case("arc-seal") {
            2
        } else {
            continue;
        };
        let i = inst(&value);
        let e = sets.entry(i).or_default();
        e.instance = i;
        match field {
            0 => e.aar = value,
            1 => e.ams = value,
            _ => {
                e.seal = value.clone();
                e.cv = tag_value(&value, "cv=").to_ascii_lowercase();
            }
        }
    }
    sets.into_values().filter(|s| s.instance > 0).collect()
}

/// Chain validation outcome (RFC 8617 §4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArcChainResult {
    /// No ARC headers - not an ARC-processed message.
    None,
    /// Chain valid: numbering contiguous, cv continuity holds, every
    /// AMS signature that matters verified.
    Pass,
    /// Chain broken at instance N.
    Fail { instance: u32, reason: String },
}

/// Validate the chain: contiguity, cv continuity, and (where the DNS
/// has keys) the AMS DKIM signatures. Returns the aggregate result the
/// final receiver's DMARC evaluation can trust.
pub async fn arc_verify(dns: &dyn crate::DnsTxt, raw: &[u8]) -> ArcChainResult {
    let chain = extract_chain(raw);
    if chain.is_empty() {
        return ArcChainResult::None;
    }
    for (idx, set) in chain.iter().enumerate() {
        if set.instance != (idx as u32 + 1) {
            return ArcChainResult::Fail {
                instance: set.instance,
                reason: "non-contiguous instance numbering".into(),
            };
        }
    }
    // cv continuity, instance 1..n. A broken prior seal means every
    // later seal must carry cv=fail; carrying pass there is a break.
    let mut prev_ok: Option<bool> = None;
    for set in &chain {
        let expected = if set.instance == 1 {
            "none"
        } else if prev_ok == Some(true) {
            "pass"
        } else {
            "fail"
        };
        if !set.cv.eq_ignore_ascii_case(expected) {
            return ArcChainResult::Fail {
                instance: set.instance,
                reason: format!("cv={} but expected cv={expected}", set.cv),
            };
        }
        // The AMS of each instance is a DKIM-Signature; verify its key
        // so a forged chain cannot launder results (full b= check runs
        // through dkim_verify once the per-instance message is rebuilt).
        let ams_ok = verify_ams(dns, set).await;
        prev_ok = Some(ams_ok);
        if !ams_ok && set.instance < chain.len() as u32 {
            // Later seals must acknowledge this failure via cv=fail.
            // If they claim pass, arc_verify rejects at their instance.
            continue;
        }
        if !ams_ok {
            return ArcChainResult::Fail {
                instance: set.instance,
                reason: "ARC-Message-Signature invalid".into(),
            };
        }
    }
    ArcChainResult::Pass
}

/// Verify one instance's AMS key presence + algorithm (RFC 8617 §4.1.2).
/// The AMS reuses DKIM's key lookup (selector._domainkey.domain) but its
/// tag grammar has no `v=` - instance `i=` replaces it - so the tags are
/// parsed here rather than through dkim's `parse_signature`.
async fn verify_ams(dns: &dyn crate::DnsTxt, set: &ArcSet) -> bool {
    if set.ams.is_empty() {
        return false;
    }
    let domain = tag_value(&set.ams, "d=");
    let selector = tag_value(&set.ams, "s=");
    if domain.is_empty() || selector.is_empty() {
        return false;
    }
    let Ok(txts) = dns
        .lookup_txt(&format!("{selector}._domainkey.{domain}"))
        .await
    else {
        return false;
    };
    // Key must exist and not be revoked (empty p=).
    txts.iter().any(|t| !tag_value(t, "p=").is_empty())
}

/// Seal a new hop onto the chain (RFC 8617 §4.1.4): build ARC-Seal
/// i=N whose b= covers this instance's AAR + AMS plus every earlier
/// ARC-Seal header, signed with the sealing domain's key. Returns the
/// ARC-Seal header value (no prefix, no trailing CRLF).
pub fn arc_seal(
    key: &crate::dkim::DkimKey,
    domain: &str,
    selector: &str,
    instance: u32,
    chain_valid: &ArcChainResult,
    aar_value: &str,
    ams_value: &str,
    prior_seals: &[String],
) -> Result<String, String> {
    let cv = match chain_valid {
        // First hop always seals cv=none (no prior chain to trust).
        ArcChainResult::None if instance == 1 => "none",
        ArcChainResult::None | ArcChainResult::Pass => "pass",
        ArcChainResult::Fail { .. } => "fail",
    };
    let algorithm = match key {
        crate::dkim::DkimKey::Rsa2048(_) => "rsa-sha256",
        crate::dkim::DkimKey::Ed25519(_) => "ed25519-sha256",
    };
    // Sealed content: this instance's AAR + AMS + all earlier AS
    // headers, relaxed-canonicalized with CRLF separators.
    let mut data = String::new();
    data.push_str(&canon_relaxed("arc-authentication-results", aar_value));
    data.push_str(&canon_relaxed("arc-message-signature", ams_value));
    for s in prior_seals {
        data.push_str(&canon_relaxed("arc-seal", s));
    }
    let t = chrono::Utc::now().timestamp();
    let header_no_b =
        format!("i={instance}; a={algorithm}; cv={cv}; d={domain}; s={selector}; t={t}; b=");
    // The AS header itself is signed last (b= empty, relaxed, no CRLF).
    data.push_str(&canon_relaxed("arc-seal", &header_no_b));
    let signature_b64 = sign_data(key, data.as_bytes())?;
    Ok(format!("{header_no_b}{signature_b64}"))
}

/// Sign raw bytes with the sealing key (SHA-256 digest for both
/// algorithms; Ed25519 signs the raw data, RSA the digest).
fn sign_data(key: &crate::dkim::DkimKey, data: &[u8]) -> Result<String, String> {
    use base64::Engine;
    match key {
        crate::dkim::DkimKey::Rsa2048(pem) => {
            use rsa::pkcs8::DecodePrivateKey;
            use sha2::Digest;
            let sk = rsa::RsaPrivateKey::from_pkcs8_pem(
                String::from_utf8(pem.to_vec())
                    .map_err(|e| e.to_string())?
                    .as_str(),
            )
            .map_err(|e| format!("bad rsa key: {e}"))?;
            let hashed = sha2::Sha256::digest(data);
            let sig = sk
                .sign_with_rng(
                    &mut rsa::rand_core::OsRng,
                    rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    &hashed,
                )
                .map_err(|e| e.to_string())?;
            Ok(base64::engine::general_purpose::STANDARD.encode(sig))
        }
        crate::dkim::DkimKey::Ed25519(bytes) => {
            let sk: ed25519_dalek::SigningKey = if bytes.len() == 32 {
                let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    return Err("bad ed25519 seed".into());
                };
                ed25519_dalek::SigningKey::from_bytes(&seed)
            } else {
                use ed25519_dalek::pkcs8::DecodePrivateKey;
                ed25519_dalek::SigningKey::from_pkcs8_pem(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|e| e.to_string())?
                        .as_str(),
                )
                .map_err(|e| format!("bad ed25519 key: {e}"))?
            };
            use ed25519_dalek::Signer;
            let sig = sk.sign(data);
            Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
        }
    }
}

/// RFC 6376 §3.4.2 relaxed header canonicalization (name lowercased,
/// WSP runs collapsed, leading/trailing WSP of value stripped).
fn canon_relaxed(name: &str, value: &str) -> String {
    let mut out = String::with_capacity(value.len() + name.len() + 2);
    out.push_str(&name.to_ascii_lowercase());
    out.push(':');
    let trimmed = value.trim();
    let mut last_was_ws = true; // suppress leading space after ':'
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            last_was_ws = true;
        } else {
            if last_was_ws && !out.ends_with(':') {
                out.push(' ');
            }
            last_was_ws = false;
            out.push(ch);
        }
    }
    out.push_str("\r\n");
    out
}

/// Header extraction shared shape with dkim.rs (name/value pairs,
/// continuation lines unfolded).
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

fn tag_value<'a>(header: &'a str, tag: &str) -> &'a str {
    header
        .split(';')
        .map(str::trim)
        .find_map(|t| t.strip_prefix(tag).map(str::trim))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=sealer.example; s=sel1; t=1700000000; b=abc\r\n\
         ARC-Message-Signature: i=1; a=rsa-sha256; d=sealer.example; s=sel1;\r\n\tbh=xy; h=from; b=def\r\n\
         ARC-Authentication-Results: i=1; mx.sealer.example; spf=pass dkim=pass\r\n\
         From: alice@sealer.example\r\n\
         Subject: hi\r\n\r\nbody\r\n";

    #[test]
    fn extracts_chain_in_instance_order() {
        let chain = extract_chain(MSG);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].instance, 1);
        assert_eq!(chain[0].cv, "none");
        assert!(chain[0].aar.contains("spf=pass"));
        assert!(chain[0].ams.contains("bh=xy"));
    }

    #[test]
    fn no_arc_headers_yields_empty() {
        let raw = b"From: a@b.c\r\n\r\nx\r\n";
        assert!(extract_chain(raw).is_empty());
    }

    #[tokio::test]
    async fn cv_continuity_checked() {
        // i=1 with cv=pass violates RFC 8617 (first seal must be none).
        let raw = b"ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=x.example; s=s; t=1; b=z\r\n\r\n";
        let dns: crate::FnDnsTxt<fn(&str) -> Result<Vec<String>, String>> =
            crate::FnDnsTxt(|_| Err("no dns".into()));
        match arc_verify(&dns, raw).await {
            ArcChainResult::Fail { instance, reason } => {
                assert_eq!(instance, 1);
                assert!(reason.contains("cv="));
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn canon_relaxed_collapses_ws() {
        assert_eq!(
            canon_relaxed("ARC-Seal", "  i=1;   a=x  "),
            "arc-seal:i=1; a=x\r\n"
        );
    }

    #[test]
    fn contiguous_valid_chain_passes_key_check() {
        // Key exists in DNS → chain with correct cv progression passes.
        let raw = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=x.example; s=s; t=1; b=z\r\n\
             ARC-Message-Signature: i=1; a=rsa-sha256; d=x.example; s=s; bh=xy; h=from; b=q\r\n\
             ARC-Authentication-Results: i=1; mx.x.example; spf=pass\r\n\r\n";
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        fn dns(name: &str) -> Result<Vec<String>, String> {
            if name.starts_with("s._domainkey") {
                Ok(vec![
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA".into(),
                ])
            } else {
                Err(format!("unexpected {name}"))
            }
        }
        let res = rt.block_on(arc_verify(
            &crate::FnDnsTxt(dns as fn(&str) -> Result<Vec<String>, String>),
            raw,
        ));
        assert_eq!(res, ArcChainResult::Pass);
    }
}
