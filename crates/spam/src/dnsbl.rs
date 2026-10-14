// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! DNSBL (DNS block-list) checks + Pyzor UDP digest client.
//!
//! DNSBL queries encode the checked element reversed into the zone
//! (e.g. `1.0.0.127.zen.spamhaus.org`); an A answer means listed, with
//! the answer value carrying the reason code. Per-element scopes
//! (RFC 5781 "Service Names"): ip / domain / url / email / from / to /
//! replyto / helo / ptr — each zone config declares which scopes it
//! applies to, and a per-check cap bounds lookups per message
//! (legacy `SpamFilterDNSBL` semantics).
//!
//! Pyzor (RFC-unpublished, de-facto protocol): UDP JSON
//! `{"Version": 1.0, "Op": "check", "OP-Digest": "…"}` to the public
//! server :24441; the response's `Count` tells how many reporters saw
//! the digest. Digest = SHA-256 (spec: SHA-1; the modern pyzor client
//! and server agree on sha256 over the normalized body).

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Which message element a zone applies to (legacy element scopes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsblScope {
    Ip,
    Domain,
    Url,
    Email,
    From,
    To,
    ReplyTo,
    Helo,
    Ptr,
}

impl DnsblScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::From => "from",
            Self::To => "to",
            Self::ReplyTo => "replyto",
            Self::Helo => "helo",
            Self::Ptr => "ptr",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "ip" => Self::Ip,
            "domain" => Self::Domain,
            "url" => Self::Url,
            "email" => Self::Email,
            "from" => Self::From,
            "to" => Self::To,
            "replyto" => Self::ReplyTo,
            "helo" => Self::Helo,
            "ptr" => Self::Ptr,
            _ => return None,
        })
    }
}

/// One configured zone (per-env config rows; design §P4.2).
#[derive(Debug, Clone)]
pub struct DnsblZone {
    pub zone: String,
    /// The scopes this zone is consulted for.
    pub scopes: Vec<DnsblScope>,
    /// Max lookups against this zone per message (0 → unlimited).
    pub max_checks_per_message: u32,
    /// If true, a listing is trusted to also cover URLs in the body
    /// (surbl-style); if false, URL elements are checked separately.
    pub trust_url: bool,
}

/// A lookup result for one element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblHit {
    pub zone: String,
    pub element: String,
    pub scope: DnsblScope,
    /// The A-record reason code (e.g. 127.0.0.4 → spam).
    pub answer: String,
}

impl DnsblZone {
    /// Build the query name for one element in this zone.
    /// - IP scopes: reversed octets (1.2.3.4 → 4.3.2.1.zone)
    /// - Domain/email scopes: the domain part (reversed-labels is
    ///   NOT used for SURBL-style zones — plain subdomain form)
    pub fn query_name(&self, element: &str, scope: DnsblScope) -> Option<String> {
        match scope {
            DnsblScope::Ip => {
                // dotted-quad IPv4 reversed; IPv6 nibbles reversed.
                if let Ok(v4) = element.parse::<std::net::Ipv4Addr>() {
                    let o = v4.octets();
                    Some(format!("{}.{}.{}.{}.{}", o[3], o[2], o[1], o[0], self.zone))
                } else if let Ok(v6) = element.parse::<std::net::Ipv6Addr>() {
                    let mut name = String::new();
                    for nib in v6.octets().iter().rev().flat_map(|b| [b & 0x0f, b >> 4]) {
                        name.push_str(&format!("{nib:x}."));
                    }
                    Some(format!("{name}{}", self.zone))
                } else {
                    None
                }
            }
            _ => {
                let host = element
                    .rsplit('@')
                    .next()
                    .unwrap_or(element)
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
                    .to_ascii_lowercase();
                if host.is_empty() {
                    None
                } else {
                    Some(format!("{host}.{}", self.zone))
                }
            }
        }
    }
}

/// A DNS resolver for DNSBL A-record lookups (injected; the Mta wires
/// the DoH/system resolver, tests use closures).
#[async_trait::async_trait]
pub trait DnsblResolver: Send + Sync {
    /// Resolve A records for a name; Ok(empty) = not listed.
    async fn lookup_a(&self, name: &str) -> Result<Vec<String>, String>;
}

/// Closure resolver for tests.
pub struct FnDnsblResolver<F>(pub F);

#[async_trait::async_trait]
impl<F> DnsblResolver for FnDnsblResolver<F>
where
    F: Fn(&str) -> Result<Vec<String>, String> + Send + Sync,
{
    async fn lookup_a(&self, name: &str) -> Result<Vec<String>, String> {
        (self.0)(name)
    }
}

/// The per-message check plan: which (element, scope) pairs exist.
#[derive(Debug, Clone, Default)]
pub struct DnsblElements {
    pub ip: Vec<String>,
    pub helo: Option<String>,
    pub from_domain: Option<String>,
    pub to_domains: Vec<String>,
    pub reply_to_domain: Option<String>,
    pub urls: Vec<String>,
}

/// Run the DNSBL checks for one message. Each zone is consulted for the
/// scopes it declares, respecting the per-message cap; results carry
/// the element + zone + answer. The caller maps hits to the `Dnsbl`
/// tag (legacy: any hit → the tag fires once, weight from config).
pub async fn check_dnsbl(
    zones: &[DnsblZone],
    elements: &DnsblElements,
    resolver: &dyn DnsblResolver,
) -> Vec<DnsblHit> {
    let mut hits: Vec<DnsblHit> = Vec::new();
    for zone in zones {
        let mut checks: u32 = 0;
        for scope in &zone.scopes {
            let element_list: Vec<String> = match scope {
                DnsblScope::Ip => elements.ip.clone(),
                DnsblScope::Helo => elements.helo.clone().into_iter().collect(),
                DnsblScope::From => elements.from_domain.clone().into_iter().collect(),
                DnsblScope::To => elements.to_domains.clone(),
                DnsblScope::ReplyTo => elements.reply_to_domain.clone().into_iter().collect(),
                DnsblScope::Url => elements.urls.clone(),
                // email/domain/ptr share the from-domain today (legacy
                // collapses them at config level).
                DnsblScope::Email | DnsblScope::Domain | DnsblScope::Ptr => {
                    elements.from_domain.clone().into_iter().collect()
                }
            };
            for element in element_list {
                if zone.max_checks_per_message > 0 && checks >= zone.max_checks_per_message {
                    break;
                }
                let Some(name) = zone.query_name(&element, *scope) else {
                    continue;
                };
                checks += 1;
                if let Ok(answers) = resolver.lookup_a(&name).await {
                    if let Some(answer) = answers.first() {
                        hits.push(DnsblHit {
                            zone: zone.zone.clone(),
                            element,
                            scope: *scope,
                            answer: answer.clone(),
                        });
                    }
                }
            }
        }
    }
    hits
}

// ── Pyzor ───────────────────────────────────────────────────────────────

/// Public Pyzor server (the de-facto default; env-configurable).
pub const PYZOR_DEFAULT_SERVER: &str = "public.pyzor.org:24441";

/// Normalize a body for digesting (pyzor semantics): collapse WSP runs,
/// drop lines that are pure punctuation noise, lowercase.
pub fn pyzor_normalize(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let mut norm = String::new();
        let mut last_ws = false;
        for ch in line.chars() {
            if ch.is_whitespace() {
                last_ws = true;
            } else {
                if last_ws && !norm.is_empty() {
                    norm.push(' ');
                }
                last_ws = false;
                norm.push(ch.to_ascii_lowercase());
            }
        }
        // Drop empty and punctuation-only lines.
        if norm.chars().any(|c| c.is_alphanumeric()) {
            out.push_str(&norm);
            out.push('\n');
        }
    }
    out
}

/// Pyzor digest: SHA-256 over the normalized body, hex-encoded
/// (sha256 replaced pyzor's original sha1 in the modern protocol).
pub fn pyzor_digest(body: &str) -> String {
    let normalized = pyzor_normalize(body);
    hex(&Sha256::digest(normalized.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Pyzor check response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyzorReport {
    /// How many reporters have seen this digest (0 = unknown content).
    pub count: i64,
    /// How many distinct reporters whitelisted it.
    pub wl_count: i64,
}

/// Query a Pyzor server over UDP for a digest. The JSON wire protocol
/// is one datagram each way: request
/// `{"Version":"1.0","Op":"check","OP-Digest":"…"}` and the response
/// carries `Count` / `WL-Count`.
pub async fn pyzor_check(server: &str, digest: &str) -> Result<PyzorReport, String> {
    let req = serde_json::json!({
        "Version": "1.0",
        "Op": "check",
        "OP-Digest": digest,
    });
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(req.to_string().as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .map_err(|_| "pyzor timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let resp: serde_json::Value =
        serde_json::from_slice(&buf[..n]).map_err(|e| format!("bad pyzor json: {e}"))?;
    Ok(PyzorReport {
        count: resp.get("Count").and_then(|v| v.as_i64()).unwrap_or(0),
        wl_count: resp.get("WL-Count").and_then(|v| v.as_i64()).unwrap_or(0),
    })
}

/// Build a zone set from env-style config rows (`zone|scopes|cap`).
pub fn zones_from_config(rows: &[(String, String, u32)]) -> Vec<DnsblZone> {
    rows.iter()
        .filter_map(|(zone, scopes, cap)| {
            let scopes: Vec<DnsblScope> =
                scopes.split(',').filter_map(DnsblScope::parse).collect();
            if scopes.is_empty() {
                return None;
            }
            Some(DnsblZone {
                zone: zone.clone(),
                trust_url: scopes.iter().any(|s| *s == DnsblScope::Url),
                scopes,
                max_checks_per_message: *cap,
            })
        })
        .collect()
}

/// Aggregate hits by zone for X-Spam-Report rendering.
pub fn hits_by_zone(hits: &[DnsblHit]) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for h in hits {
        *out.entry(h.zone.clone()).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_name_reverses_ipv4() {
        let z = DnsblZone {
            zone: "zen.spamhaus.org".into(),
            scopes: vec![DnsblScope::Ip],
            max_checks_per_message: 0,
            trust_url: false,
        };
        assert_eq!(
            z.query_name("1.2.3.4", DnsblScope::Ip).unwrap(),
            "4.3.2.1.zen.spamhaus.org"
        );
        // 127.0.0.1 (loopback) is never a real listing source but the
        // reversal math is the same.
        assert_eq!(
            z.query_name("127.0.0.1", DnsblScope::Ip).unwrap(),
            "1.0.0.127.zen.spamhaus.org"
        );
    }

    #[test]
    fn query_name_domains_plain_subdomain() {
        let z = DnsblZone {
            zone: "multi.surbl.org".into(),
            scopes: vec![DnsblScope::Domain],
            max_checks_per_message: 0,
            trust_url: true,
        };
        assert_eq!(
            z.query_name("spam.example.com", DnsblScope::Domain).unwrap(),
            "spam.example.com.multi.surbl.org"
        );
        // Email scope hashes on the domain part.
        assert_eq!(
            z.query_name("user@spam.example.com", DnsblScope::Email).unwrap(),
            "spam.example.com.multi.surbl.org"
        );
    }

    #[tokio::test]
    async fn listed_ip_produces_hit() {
        let zones = vec![DnsblZone {
            zone: "bl.example".into(),
            scopes: vec![DnsblScope::Ip],
            max_checks_per_message: 0,
            trust_url: false,
        }];
        let elements = DnsblElements {
            ip: vec!["9.9.9.9".into()],
            ..Default::default()
        };
        fn resolver(name: &str) -> Result<Vec<String>, String> {
            if name == "9.9.9.9.bl.example" {
                Ok(vec!["127.0.0.2".into()])
            } else {
                Ok(vec![])
            }
        }
        let resolver = FnDnsblResolver(resolver as fn(&str) -> Result<Vec<String>, String>);
        let hits = check_dnsbl(&zones, &elements, &resolver).await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].answer, "127.0.0.2");
        assert_eq!(hits[0].zone, "bl.example");
    }

    #[tokio::test]
    async fn per_message_cap_respected() {
        let zones = vec![DnsblZone {
            zone: "bl.example".into(),
            scopes: vec![DnsblScope::Ip],
            max_checks_per_message: 1,
            trust_url: false,
        }];
        let elements = DnsblElements {
            ip: vec!["1.1.1.1".into(), "2.2.2.2".into()],
            ..Default::default()
        };
        fn resolver(_: &str) -> Result<Vec<String>, String> {
            Ok(vec!["127.0.0.2".into()])
        }
        let resolver = FnDnsblResolver(resolver as fn(&str) -> Result<Vec<String>, String>);
        let hits = check_dnsbl(&zones, &elements, &resolver).await;
        // Cap = 1 → only the first element checked.
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn pyzor_digest_stable_and_ws_normalized() {
        let a = pyzor_digest("Hello   WORLD\r\n\r\n!!! ...\r\nfoo bar");
        let b = pyzor_digest("hello world\nfoo  bar\n");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn zones_from_config_parses() {
        let zones = zones_from_config(&[
            ("zen.spamhaus.org".into(), "ip".into(), 5),
            ("multi.surbl.org".into(), "domain,url".into(), 10),
        ]);
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0].scopes, vec![DnsblScope::Ip]);
        assert!(zones[1].trust_url);
    }
}