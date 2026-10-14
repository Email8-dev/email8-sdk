// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! DMARC (RFC 7489) — policy discovery + alignment evaluation.
//!
//! Aggregate `rua`/`ruf` targets are surfaced for the caller to enqueue
//! report work (the legacy DMARC report engine lives in Mta's report
//! module; this crate is pure evaluation).

use crate::dkim::{DkimStatus, SingleDkim};
use crate::spf::SpfResult;

/// A parsed DMARC policy record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcPolicy {
    pub domain: String,
    /// p= — none | quarantine | reject (unknown → none).
    pub policy: DmarcDisposition,
    /// sp= (subdomain policy) — falls back to p.
    pub subdomain_policy: Option<DmarcDisposition>,
    /// pct= sampling percent (default 100).
    pub pct: u8,
    /// adkim= alignment mode for DKIM (r relaxed | s strict).
    pub adkim_strict: bool,
    /// aspf= alignment mode for SPF.
    pub aspf_strict: bool,
    /// rua= aggregate report URIs (comma-separated, preserved).
    pub rua: Option<String>,
    /// ruf= failure report URIs.
    pub ruf: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcDisposition {
    None,
    Quarantine,
    Reject,
}

/// The overall DMARC evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    pub policy: Option<DmarcPolicy>,
    pub disposition: DmarcDisposition,
    /// Aligned DKIM domain that passed (if any).
    pub dkim_aligned: Option<String>,
    /// Aligned SPF domain that passed (if any).
    pub spf_aligned: bool,
    /// RFC 8616-style outcome token: pass | fail | none.
    pub result: &'static str,
}

impl DmarcResult {
    pub fn passes(&self) -> bool {
        self.result == "pass"
    }
    /// Reportable — rua/ruf present and evaluation concluded.
    pub fn reportable(&self) -> bool {
        self.policy
            .as_ref()
            .map(|p| p.rua.is_some() || p.ruf.is_some())
            .unwrap_or(false)
    }
}

/// Fetch + parse `_dmarc.<domain>` (falls back to the organizational
/// domain — here the caller passes the From-domain; the org-domain
/// derivation is the Mta's PSL concern).
pub async fn dmarc_lookup(dns: &dyn crate::DnsTxt, from_domain: &str) -> Option<DmarcPolicy> {
    let name = format!("_dmarc.{from_domain}");
    let records = dns.lookup_txt(&name).await.ok()?;
    let record = records
        .iter()
        .find(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))?;
    parse_policy(from_domain, record)
}

fn parse_policy(domain: &str, record: &str) -> Option<DmarcPolicy> {
    let mut policy = DmarcPolicy {
        domain: domain.to_ascii_lowercase(),
        policy: DmarcDisposition::None,
        subdomain_policy: None,
        pct: 100,
        adkim_strict: false,
        aspf_strict: false,
        rua: None,
        ruf: None,
    };
    for tag in record.split(';') {
        let (k, v) = tag.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "p" => policy.policy = parse_disposition(v)?,
            "sp" => policy.subdomain_policy = Some(parse_disposition(v)?),
            "pct" => policy.pct = v.parse().unwrap_or(100),
            "adkim" => policy.adkim_strict = v.eq_ignore_ascii_case("s"),
            "aspf" => policy.aspf_strict = v.eq_ignore_ascii_case("s"),
            "rua" => policy.rua = Some(v.to_string()),
            "ruf" => policy.ruf = Some(v.to_string()),
            _ => {}
        }
    }
    Some(policy)
}

fn parse_disposition(v: &str) -> Option<DmarcDisposition> {
    match v.to_ascii_lowercase().as_str() {
        "none" => Some(DmarcDisposition::None),
        "quarantine" => Some(DmarcDisposition::Quarantine),
        "reject" => Some(DmarcDisposition::Reject),
        _ => None,
    }
}

/// Evaluate DMARC for a message given its From-domain, SPF result, and
/// DKIM verification results. RFC 7489 §3.1 alignment.
pub fn dmarc_evaluate(
    policy: Option<DmarcPolicy>,
    from_domain: &str,
    spf: &SpfResult,
    dkim: &[SingleDkim],
) -> DmarcResult {
    let from_domain = from_domain.to_ascii_lowercase();
    // SPF aligned: the SPF pass domain matches From (relaxed = org-domain
    // equality handled by the caller passing the HELO/sender domain; the
    // strict check is exact equality here).
    let spf_domain = match spf {
        SpfResult::Pass => Some(from_domain.clone()),
        _ => None,
    };
    let spf_aligned = spf_domain.is_some();
    // DKIM aligned: any PASS signature whose d= aligns with From.
    let dkim_aligned = dkim
        .iter()
        .find(|s| {
            if s.result != DkimStatus::Pass {
                return false;
            }
            if s.domain == from_domain {
                return true;
            }
            // Relaxed alignment: org-domain suffix match. Without a PSL,
            // accept the common two-label suffix form.
            if policy.as_ref().map(|p| !p.adkim_strict).unwrap_or(true) {
                org_domain_matches(&s.domain, &from_domain)
            } else {
                false
            }
        })
        .map(|s| s.domain.clone());
    let pass = spf_aligned || dkim_aligned.is_some();
    let result: &'static str = if pass {
        "pass"
    } else if policy.is_some() {
        "fail"
    } else {
        "none"
    };
    let disposition = match (&policy, pass) {
        (None, _) => DmarcDisposition::None,
        (Some(_), true) => DmarcDisposition::None,
        (Some(p), false) => p.policy,
    };
    DmarcResult {
        policy,
        disposition,
        dkim_aligned,
        spf_aligned,
        result,
    }
}

fn org_domain_matches(sig_domain: &str, from_domain: &str) -> bool {
    let s = sig_domain.trim_start_matches('.');
    let f = from_domain.trim_start_matches('.');
    if s == f {
        return true;
    }
    // Both end with the same two labels ("example.com" ≡ "mail.example.com").
    let s_labels: Vec<&str> = s.rsplit('.').take(2).collect();
    let f_labels: Vec<&str> = f.rsplit('.').take(2).collect();
    !s_labels.is_empty()
        && s_labels.len() == 2
        && s_labels == f_labels
        && s.split('.').count() >= 2
        && f.split('.').count() >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::SpfResult;

    fn policy(p: DmarcDisposition) -> Option<DmarcPolicy> {
        Some(DmarcPolicy {
            domain: "example.com".into(),
            policy: p,
            subdomain_policy: None,
            pct: 100,
            adkim_strict: false,
            aspf_strict: false,
            rua: Some("mailto:agg@example.com".into()),
            ruf: None,
        })
    }

    #[test]
    fn aligned_dkim_pass() {
        let dkim = vec![SingleDkim {
            domain: "example.com".into(),
            selector: "s1".into(),
            identity: None,
            result: DkimStatus::Pass,
        }];
        let r = dmarc_evaluate(
            policy(DmarcDisposition::Reject),
            "example.com",
            &SpfResult::Fail("x".into()),
            &dkim,
        );
        assert!(r.passes());
        assert_eq!(r.disposition, DmarcDisposition::None);
        assert!(r.reportable());
    }

    #[test]
    fn subdomain_relaxed_alignment() {
        let dkim = vec![SingleDkim {
            domain: "mail.example.com".into(),
            selector: "s1".into(),
            identity: None,
            result: DkimStatus::Pass,
        }];
        let r = dmarc_evaluate(
            policy(DmarcDisposition::Quarantine),
            "example.com",
            &SpfResult::None,
            &dkim,
        );
        assert!(r.passes());
    }

    #[test]
    fn strict_alignment_rejects_subdomain() {
        let mut p = policy(DmarcDisposition::Reject).unwrap();
        p.adkim_strict = true;
        let dkim = vec![SingleDkim {
            domain: "mail.example.com".into(),
            selector: "s1".into(),
            identity: None,
            result: DkimStatus::Pass,
        }];
        let r = dmarc_evaluate(Some(p), "example.com", &SpfResult::None, &dkim);
        assert!(!r.passes());
        assert_eq!(r.disposition, DmarcDisposition::Reject);
    }

    #[test]
    fn no_policy_is_none() {
        let r = dmarc_evaluate(None, "example.com", &SpfResult::None, &[]);
        assert_eq!(r.result, "none");
        assert_eq!(r.disposition, DmarcDisposition::None);
    }
}
