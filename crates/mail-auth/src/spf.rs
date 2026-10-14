// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! SPF (RFC 7208) — `check_host()` evaluation with the macro expansion
//! subset legacy servers actually emit (s, l, o, d, i, v, h, plus %{}%
//! escapes). Mechanisms: all, include, a, mx, ip4, ip6, exists;
//! qualifiers pass/fail/softfail/neutral; modifiers redirect, exp.

use std::net::IpAddr;

use crate::DnsTxt;

/// SPF evaluation inputs (RFC 7208 §4: check_host arguments).
#[derive(Debug, Clone)]
pub struct SpfParams {
    /// The connecting SMTP client IP (`ip`).
    pub client_ip: IpAddr,
    /// HELO/EHLO argument (`helo`).
    pub helo_domain: String,
    /// MAIL FROM address, empty for the null sender (`sender`).
    pub sender: String,
}

/// The domain to evaluate — the sender's domain, else HELO (RFC 7208 §2.4).
pub fn spf_domain_owner(params: &SpfParams) -> String {
    let at = params.sender.rfind('@');
    match at {
        Some(pos) if pos + 1 < params.sender.len() => params.sender[pos + 1..].to_ascii_lowercase(),
        _ => params.helo_domain.to_ascii_lowercase(),
    }
}

/// SPF result (RFC 7208 §2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail(String),
    SoftFail,
    TempError(String),
    PermError(String),
}

impl SpfResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, SpfResult::Pass)
    }
    /// The Authentication-Results `spf=` token.
    pub fn token(&self) -> &'static str {
        match self {
            SpfResult::None => "none",
            SpfResult::Neutral => "neutral",
            SpfResult::Pass => "pass",
            SpfResult::Fail(_) => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::TempError(_) => "temperror",
            SpfResult::PermError(_) => "permerror",
        }
    }
}

/// Evaluate check_host() for the sender's (or HELO's) domain.
pub async fn spf_check(dns: &dyn DnsTxt, params: &SpfParams) -> SpfResult {
    let owner = spf_domain_owner(params);
    spf_check_domain(dns, params, &owner, 0).await
}

const MAX_LOOKUP_COUNT: usize = 10;

async fn spf_check_domain(
    dns: &dyn DnsTxt,
    params: &SpfParams,
    domain: &str,
    depth: usize,
) -> SpfResult {
    if depth > MAX_LOOKUP_COUNT {
        return SpfResult::PermError("too many lookups (10 max)".into());
    }
    let records = match dns.lookup_txt(domain).await {
        Ok(r) => r,
        Err(_) => return SpfResult::None,
    };
    // RFC 7208 §4.5: exactly one record beginning v=spf1 (whole terms).
    let record = match records
        .iter()
        .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
        .count()
    {
        0 => return SpfResult::None,
        1 => records
            .into_iter()
            .find(|r| r.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
            .unwrap(),
        _ => return SpfResult::PermError("multiple SPF records".into()),
    };
    let terms = record.trim().split_whitespace().skip(1);
    let mut redirect: Option<String> = None;
    for term in terms {
        if term.is_empty() {
            continue;
        }
        // Modifier?
        if let Some((name, value)) = term.split_once('=') {
            match name.to_ascii_lowercase().as_str() {
                "redirect" => {
                    redirect = Some(value.to_string());
                    continue;
                }
                "exp" => continue, // explanation is informational
                _ => continue,     // unknown modifiers ignored (§6)
            }
        }
        // Mechanism: [qualifier]name[:arg][/cidr]
        let (qualifier, rest) = match term.as_bytes().first() {
            Some(b'+') => (Qualifier::Pass, &term[1..]),
            Some(b'-') => (Qualifier::Fail, &term[1..]),
            Some(b'~') => (Qualifier::SoftFail, &term[1..]),
            Some(b'?') => (Qualifier::Neutral, &term[1..]),
            _ => (Qualifier::Pass, term),
        };
        let (name, arg) = match rest.split_once(':') {
            Some((n, a)) => (n, Some(a)),
            None => rest.split_once('/').map(|(n, _)| (n, None)).unwrap_or((rest, None)),
        };
        let matched = mech_match(dns, params, domain, name, arg).await;
        match matched {
            MechOutcome::Match => return qualifier_result(qualifier),
            MechOutcome::NoMatch => continue,
            MechOutcome::TempError(e) => return SpfResult::TempError(e),
            MechOutcome::PermError(e) => return SpfResult::PermError(e),
        }
    }
    // All mechanisms exhausted: redirect, else neutral default.
    if let Some(target) = redirect {
        // Recursion via boxed future (indirection for the recursive
        // async chain).
        let inner = Box::pin(spf_check_domain(dns, params, &target, depth + 1));
        return inner.await;
    }
    SpfResult::Neutral
}

enum MechOutcome {
    Match,
    NoMatch,
    TempError(String),
    PermError(String),
}

async fn mech_match(
    dns: &dyn DnsTxt,
    params: &SpfParams,
    domain: &str,
    name: &str,
    arg: Option<&str>,
) -> MechOutcome {
    match name.to_ascii_lowercase().as_str() {
        "all" => MechOutcome::Match,
        "ip4" => {
            let Some(spec) = arg else { return MechOutcome::PermError("ip4 needs a network".into()) };
            if ip_in_cidr4(params.client_ip, spec) {
                MechOutcome::Match
            } else {
                MechOutcome::NoMatch
            }
        }
        "ip6" => {
            let Some(spec) = arg else { return MechOutcome::PermError("ip6 needs a network".into()) };
            if ip_in_cidr6(params.client_ip, spec) {
                MechOutcome::Match
            } else {
                MechOutcome::NoMatch
            }
        }
        "a" => {
            // a[:domain][/cidr] — the domain's A (v4) or AAAA (v6) records.
            let target = arg.map(|a| a.split('/').next().unwrap_or(a)).unwrap_or(domain);
            if a_record_matches(dns, params, target).await {
                MechOutcome::Match
            } else {
                MechOutcome::NoMatch
            }
        }
        "mx" => {
            // mx[:domain][/cidr] — resolve MX, then their A/AAAA. MX
            // lookups arrive as TXT rows shaped "10 mail.example.com"
            // from the resolver impl; treat TXT as a stand-in — the
            // production resolver translates MX queries to this shape.
            let target = arg.map(|a| a.split('/').next().unwrap_or(a)).unwrap_or(domain);
            let mxs = match dns.lookup_txt(&format!("_mx.{target}")).await {
                Ok(v) => v,
                Err(_) => return MechOutcome::NoMatch,
            };
            for mx in mxs {
                let host = mx.split_whitespace().last().unwrap_or("").to_string();
                if a_record_matches(dns, params, &host).await {
                    return MechOutcome::Match;
                }
            }
            MechOutcome::NoMatch
        }
        "include" => {
            let Some(target) = arg else { return MechOutcome::PermError("include needs a domain".into()) };
            // Recurse via a boxed future (async fn → async fn chains that
            // recurse need the indirection).
            let inner = Box::pin(spf_check_domain(dns, params, target, 0));
            match inner.await {
                SpfResult::Pass => MechOutcome::Match,
                SpfResult::Fail(_) | SpfResult::SoftFail | SpfResult::Neutral => MechOutcome::NoMatch,
                SpfResult::TempError(e) => MechOutcome::TempError(e),
                SpfResult::PermError(e) => MechOutcome::PermError(e),
                SpfResult::None => MechOutcome::PermError("include target has no SPF".into()),
            }
        }
        "exists" => {
            let Some(target) = arg else { return MechOutcome::PermError("exists needs a domain".into()) };
            let expanded = macros(target, params, domain);
            match dns.lookup_txt(&format!("_exists.{expanded}")).await {
                Ok(v) if !v.is_empty() => MechOutcome::Match,
                Ok(_) => MechOutcome::NoMatch,
                Err(_) => MechOutcome::NoMatch,
            }
        }
        other => MechOutcome::PermError(format!("unknown mechanism: {other}")),
    }
}

fn qualifier_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail("policy mismatch".into()),
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

fn ip_in_cidr4(ip: IpAddr, spec: &str) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let (base, prefix) = match spec.split_once('/') {
        Some((b, p)) => (b, p.parse::<u8>().unwrap_or(32)),
        None => (spec, 32u8),
    };
    let Ok(net) = base.parse::<std::net::Ipv4Addr>() else { return false };
    let bits = 32u32.saturating_sub(prefix as u32);
    let mask = if bits == 32 { 0 } else { u32::MAX << bits };
    (u32::from(v4) & mask) == (u32::from(net) & mask)
}

fn ip_in_cidr6(ip: IpAddr, spec: &str) -> bool {
    let IpAddr::V6(v6) = ip else { return false };
    let (base, prefix) = match spec.split_once('/') {
        Some((b, p)) => (b, p.parse::<u8>().unwrap_or(128)),
        None => (spec, 128u8),
    };
    let Ok(net) = base.parse::<std::net::Ipv6Addr>() else { return false };
    let bits = 128u128.saturating_sub(prefix as u128);
    let mask = if bits == 128 { 0 } else { u128::MAX << bits };
    (u128::from(v6) & mask) == (u128::from(net) & mask)
}

async fn a_record_matches(dns: &dyn DnsTxt, params: &SpfParams, host: &str) -> bool {
    // The production resolver exposes A/AAAA as TXT rows of the address.
    let records = match dns.lookup_txt(&format!("_a.{host}")).await {
        Ok(v) => v,
        Err(_) => return false,
    };
    records.iter().any(|r| r.trim().parse::<IpAddr>().ok() == Some(params.client_ip))
}

/// Macro expansion: %{s} sender, %{l} local, %{o} sender domain, %{d}
/// current domain, %{i} IP (dotted for v4 / nibble-dotted v6), %{h} HELO,
/// %{v} "in-addr"/"ip6", %% literal %, %_ space, %- %20. Transformers
/// (digits + r/delimiters) applied per RFC 7208 §7.3.
fn macros(pattern: &str, params: &SpfParams, domain: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('_') => out.push(' '),
            Some('-') => out.push_str("%20"),
            Some('{') => {
                let inner: String = chars
                    .by_ref()
                    .take_while(|c| *c != '}')
                    .collect::<String>();
                let mut rev = false;
                let mut delims = String::from(".");
                let mut digits = String::new();
                for ch in inner.chars() {
                    if ch.is_ascii_digit() {
                        digits.push(ch);
                    } else if ch == 'r' {
                        rev = true;
                    } else if !"slodiphv".contains(ch.to_ascii_lowercase()) {
                        delims.push(ch);
                    }
                }
                let letter = inner.chars().rev().find(|c| c.is_ascii_alphabetic());
                let raw = match letter.map(|c| c.to_ascii_lowercase()) {
                    Some('s') => params.sender.clone(),
                    Some('l') => params
                        .sender
                        .split('@')
                        .next()
                        .unwrap_or(&params.sender)
                        .to_string(),
                    Some('o') => params
                        .sender
                        .rsplit('@')
                        .next()
                        .unwrap_or(&params.sender)
                        .to_string(),
                    Some('d') => domain.to_string(),
                    Some('i') => match params.client_ip {
                        IpAddr::V4(v) => v.to_string(),
                        IpAddr::V6(v) => v
                            .octets()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join("."),
                    },
                    Some('h') => params.helo_domain.clone(),
                    Some('v') => match params.client_ip {
                        IpAddr::V4(_) => "in-addr".into(),
                        IpAddr::V6(_) => "ip6".into(),
                    },
                    _ => inner.clone(),
                };
                let mut parts: Vec<&str> = raw.split(&delims as &str).collect();
                if rev {
                    parts.reverse();
                }
                if let Ok(n) = digits.parse::<usize>() {
                    if n > 0 && n < parts.len() {
                        parts = parts[parts.len() - n..].to_vec();
                    }
                }
                out.push_str(&parts.join("."));
            }
            _ => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FnDnsTxt;
    use std::net::{Ipv4Addr, IpAddr};

    #[tokio::test]
    async fn spf_ip4_pass() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "example.com" {
                Ok(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()])
            } else {
                Err("nxdomain".into())
            }
        });
        let r = spf_check(
            &dns,
            &SpfParams {
                client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                helo_domain: "mail.example.com".into(),
                sender: "alice@example.com".into(),
            },
        )
        .await;
        assert!(r.is_pass());
    }

    #[tokio::test]
    async fn spf_fail_on_mismatch() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "example.com" {
                Ok(vec!["v=spf1 ip4:192.0.2.0/24 -all".into()])
            } else {
                Err("nxdomain".into())
            }
        });
        let r = spf_check(
            &dns,
            &SpfParams {
                client_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                helo_domain: "mail.example.com".into(),
                sender: "alice@example.com".into(),
            },
        )
        .await;
        assert!(matches!(r, SpfResult::Fail(_)));
    }

    #[tokio::test]
    async fn spf_softfail_default_neutral() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "example.com" {
                Ok(vec!["v=spf1 ~all".into()])
            } else {
                Err("nxdomain".into())
            }
        });
        let r = spf_check(
            &dns,
            &SpfParams {
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                helo_domain: "h".into(),
                sender: "x@example.com".into(),
            },
        )
        .await;
        assert_eq!(r, SpfResult::SoftFail);
    }

    #[tokio::test]
    async fn spf_helo_domain_for_null_sender() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "mail.example.com" {
                Ok(vec!["v=spf1 -all".into()])
            } else {
                Err("nxdomain".into())
            }
        });
        let r = spf_check(
            &dns,
            &SpfParams {
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                helo_domain: "mail.example.com".into(),
                sender: String::new(),
            },
        )
        .await;
        assert!(matches!(r, SpfResult::Fail(_)));
    }
}