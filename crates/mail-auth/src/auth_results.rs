// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Authentication-Results (RFC 8601) builder - the `auth` header Mta
//! prepends after the inbound pipeline, plus the Received-SPF header.

use crate::dkim::{DkimStatus, SingleDkim};
use crate::dmarc::DmarcResult;
use crate::spf::SpfResult;

/// One `method=value (comment)` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub method: &'static str,
    pub value: &'static str,
    pub reason: Option<String>,
    /// `header.d=` / `smtp.mail=` style property.
    pub property: Option<(String, String)>,
}

/// The full Authentication-Results header value (after the authserv-id).
#[derive(Debug, Clone, Default)]
pub struct AuthenticationResults {
    pub results: Vec<AuthResult>,
}

impl AuthenticationResults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(mut self, r: AuthResult) -> Self {
        self.results.push(r);
        self
    }

    /// Render the complete header (name + value + CRLF).
    pub fn render(&self, authserv_id: &str) -> String {
        let mut parts = vec![authserv_id.to_string()];
        for r in &self.results {
            let mut entry = format!("{}={}", r.method, r.value);
            if let Some((pk, pv)) = &r.property {
                entry.push_str(&format!(" {pk}={pv}"));
            }
            if let Some(reason) = &r.reason {
                entry.push_str(&format!(" reason=\"{reason}\""));
            }
            parts.push(entry);
        }
        format!("Authentication-Results: {}\r\n", parts.join(";\n\t"))
    }
}

/// Build the standard set from the pipeline outcomes.
pub fn build_results(
    _authserv_id: &str,
    spf: &SpfResult,
    spf_domain: &str,
    dkim: &[SingleDkim],
    dmarc: &DmarcResult,
) -> AuthenticationResults {
    let mut ar = AuthenticationResults::new();
    // SPF - `spf=token smtp.mail=<domain>`.
    ar = ar.push(AuthResult {
        method: "spf",
        value: spf.token(),
        reason: match spf {
            SpfResult::Fail(m) | SpfResult::TempError(m) | SpfResult::PermError(m) => {
                Some(m.clone())
            }
            _ => None,
        },
        property: Some(("smtp.mail".into(), spf_domain.to_string())),
    });
    // DKIM - one entry per signature.
    for s in dkim {
        ar = ar.push(AuthResult {
            method: "dkim",
            value: s.result.token(),
            reason: match &s.result {
                DkimStatus::Fail(m) | DkimStatus::TempError(m) | DkimStatus::PermError(m) => {
                    Some(m.clone())
                }
                _ => None,
            },
            property: Some(("header.d".into(), s.domain.clone())),
        });
    }
    // DMARC - `dmarc=pass (p=none dis=none) header.from=<domain>`.
    let mut reason = String::new();
    if let Some(p) = &dmarc.policy {
        reason = format!(
            "p={}{} dis={}",
            match p.policy {
                crate::dmarc::DmarcDisposition::None => "none",
                crate::dmarc::DmarcDisposition::Quarantine => "quarantine",
                crate::dmarc::DmarcDisposition::Reject => "reject",
            },
            p.subdomain_policy.map(|_| "").unwrap_or_default(),
            match dmarc.disposition {
                crate::dmarc::DmarcDisposition::None => "none",
                crate::dmarc::DmarcDisposition::Quarantine => "quarantine",
                crate::dmarc::DmarcDisposition::Reject => "reject",
            }
        );
    }
    ar = ar.push(AuthResult {
        method: "dmarc",
        value: dmarc.result,
        reason: (!reason.is_empty()).then_some(reason),
        property: Some((
            "header.from".into(),
            dmarc
                .policy
                .as_ref()
                .map(|p| p.domain.clone())
                .unwrap_or_default(),
        )),
    });
    ar
}

/// The Received-SPF header (legacy parity - always emitted).
pub fn received_spf(spf: &SpfResult, params_comment: &str) -> String {
    let value = match spf {
        SpfResult::None => "none",
        SpfResult::Neutral => "neutral",
        SpfResult::Pass => "pass",
        SpfResult::Fail(_) => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::TempError(_) => "temperror",
        SpfResult::PermError(_) => "permerror",
    };
    format!("Received-SPF: {value} ({params_comment})\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_standard_set() {
        let spf = SpfResult::Pass;
        let dkim = vec![SingleDkim {
            domain: "example.com".into(),
            selector: "s1".into(),
            identity: None,
            result: DkimStatus::Pass,
        }];
        let dmarc = DmarcResult {
            policy: None,
            disposition: crate::dmarc::DmarcDisposition::None,
            dkim_aligned: Some("example.com".into()),
            spf_aligned: true,
            result: "pass",
        };
        let ar = build_results("mail.example.com", &spf, "example.com", &dkim, &dmarc);
        let hdr = ar.render("mail.example.com");
        assert!(hdr.contains("spf=pass"));
        assert!(hdr.contains("dkim=pass"));
        assert!(hdr.contains("dmarc=pass"));
    }
}
