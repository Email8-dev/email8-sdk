// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 spam engine - deterministic tag scoring (port of the legacy
//! chain), URL/phishing heuristics, and an FTRL classifier core
//! (feature hashing + per-recipient personalization support).
//! DNSBL/Pyzor network probes are injected by the caller (Mta) - the
//! engine itself is pure so it can be tested and run in-process at
//! ingest time.

pub mod classifier;
pub mod dnsbl;
pub mod rules;
pub mod url;

pub use classifier::{classify, Features, FtrlModel, TrainOutcome};
pub use dnsbl::{
    check_dnsbl, pyzor_check, pyzor_digest, DnsblElements, DnsblHit, DnsblResolver, DnsblScope,
    DnsblZone, FnDnsblResolver,
};
pub use rules::{evaluate_tags, SpamVerdict, TagOutcome, TagSet, TagThresholds};
pub use url::{scan_urls, UrlFindings};

/// The full unauthenticated-session evaluation outcome.
#[derive(Debug, Clone)]
pub struct SpamReport {
    pub verdict: SpamVerdict,
    pub score_pct: u8,
    pub tags: Vec<TagOutcome>,
    pub urls: Vec<UrlFindings>,
    pub model_pct: Option<u8>,
}

impl SpamReport {
    /// X-Spam-Status header value (`Yes/No, score=… tags=…`).
    pub fn status_header(&self) -> String {
        let yes = matches!(self.verdict, SpamVerdict::Discard | SpamVerdict::Quarantine);
        let tags: Vec<String> = self
            .tags
            .iter()
            .filter(|t| t.hit)
            .map(|t| t.tag.as_str().to_string())
            .collect();
        format!(
            "{}, score={}{}",
            if yes { "Yes" } else { "No" },
            self.score_pct,
            if tags.is_empty() {
                String::new()
            } else {
                format!(" tags={}", tags.join(","))
            }
        )
    }

    /// X-Spam-Score header value (percentage 0-100).
    pub fn score_header(&self) -> String {
        format!("{}", self.score_pct)
    }

    /// X-Spam-Result header value (Allow/Discard/Reject/Quarantine).
    pub fn result_header(&self) -> String {
        match self.verdict {
            SpamVerdict::Allow => "Allow".into(),
            SpamVerdict::Quarantine => "Quarantine".into(),
            SpamVerdict::Discard => "Discard".into(),
            SpamVerdict::Reject => "Reject".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_render() {
        let report = SpamReport {
            verdict: SpamVerdict::Quarantine,
            score_pct: 62,
            tags: vec![
                TagOutcome {
                    tag: TagSet::Subject,
                    hit: true,
                    weight: 30,
                },
                TagOutcome {
                    tag: TagSet::Url,
                    hit: false,
                    weight: 0,
                },
            ],
            urls: vec![],
            model_pct: Some(70),
        };
        assert!(report.status_header().contains("Yes"));
        assert!(report.status_header().contains("tags=subject"));
        assert_eq!(report.score_header(), "62");
        assert_eq!(report.result_header(), "Quarantine");
    }
}
