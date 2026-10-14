// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Tag-based scoring — the legacy stage-chain port. Each tag has a
//! weight; the sum (capped at 100) crosses thresholds →
//! Allow / Quarantine / Discard / Reject.

use serde::{Deserialize, Serialize};

/// The spam stages (legacy chain order preserved for parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagSet {
    Ip,
    Dmarc,
    Ehlo,
    Headers,
    Received,
    MessageId,
    Date,
    Subject,
    From,
    ReplyTo,
    Recipient,
    DomainReputation,
    Url,
    Mime,
    Html,
    Pyzor,
    Dnsbl,
    SpamTrap,
    Classifier,
    Rules,
}

impl TagSet {
    pub fn as_str(&self) -> &'static str {
        match self {
            TagSet::Ip => "ip",
            TagSet::Dmarc => "dmarc",
            TagSet::Ehlo => "ehlo",
            TagSet::Headers => "headers",
            TagSet::Received => "received",
            TagSet::MessageId => "messageid",
            TagSet::Date => "date",
            TagSet::Subject => "subject",
            TagSet::From => "from",
            TagSet::ReplyTo => "replyto",
            TagSet::Recipient => "recipient",
            TagSet::DomainReputation => "domain-reputation",
            TagSet::Url => "url",
            TagSet::Mime => "mime",
            TagSet::Html => "html",
            TagSet::Pyzor => "pyzor",
            TagSet::Dnsbl => "dnsbl",
            TagSet::SpamTrap => "spam-trap",
            TagSet::Classifier => "classifier",
            TagSet::Rules => "rules",
        }
    }
}

/// Per-env threshold configuration (defaults = legacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagThresholds {
    pub quarantine_at: u8,
    pub discard_at: u8,
    pub reject_at: u8,
    /// Per-tag weight overrides (missing → default).
    pub tag_weights: std::collections::BTreeMap<String, u8>,
}

impl Default for TagThresholds {
    fn default() -> Self {
        Self {
            quarantine_at: 50,
            discard_at: 75,
            reject_at: 90,
            tag_weights: Default::default(),
        }
    }
}

/// One evaluated tag.
#[derive(Debug, Clone)]
pub struct TagOutcome {
    pub tag: TagSet,
    pub hit: bool,
    pub weight: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamVerdict {
    /// Score below quarantine — deliver (INBOX).
    Allow,
    /// ≥ quarantine — deliver re-filed to JUNK by the ingest path.
    Quarantine,
    /// ≥ discard — silently drop.
    Discard,
    /// ≥ reject — refuse at the protocol level (inbound sessions).
    Reject,
}

/// Default weights per tag. Calibrated so:
/// - DNSBL alone crosses quarantine (55)
/// - a DNSBL + URL + rules + headers stack crosses discard but not reject (85)
/// - a spam-trap hit is an instant reject (100)
fn default_weight(tag: &TagSet) -> u8 {
    match tag {
        TagSet::Dnsbl => 55,
        TagSet::SpamTrap => 100,
        TagSet::Classifier => 45,
        TagSet::Url => 15,
        TagSet::Dmarc => 20,
        TagSet::Pyzor => 35,
        TagSet::Rules => 10,
        _ => 5,
    }
}

/// Evaluate the tag outcomes into a verdict. `hits` are the tags that
/// fired for this message.
pub fn evaluate_tags(hits: &[TagSet], thresholds: &TagThresholds) -> (SpamVerdict, Vec<TagOutcome>) {
    let mut outcomes = Vec::new();
    let mut total: u32 = 0;
    for tag in hits {
        let key = tag.as_str();
        let weight = thresholds
            .tag_weights
            .get(key)
            .copied()
            .unwrap_or_else(|| default_weight(tag));
        total += weight as u32;
        outcomes.push(TagOutcome { tag: *tag, weight, hit: true });
    }
    let pct = total.min(100) as u8;
    let verdict = if pct >= thresholds.reject_at {
        SpamVerdict::Reject
    } else if pct >= thresholds.discard_at {
        SpamVerdict::Discard
    } else if pct >= thresholds.quarantine_at {
        SpamVerdict::Quarantine
    } else {
        SpamVerdict::Allow
    };
    (verdict, outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnsbl_alone_quarantines() {
        let (verdict, _) = evaluate_tags(&[TagSet::Dnsbl], &TagThresholds::default());
        assert_eq!(verdict, SpamVerdict::Quarantine);
    }

    #[test]
    fn spam_trap_rejects() {
        let (verdict, _) = evaluate_tags(&[TagSet::SpamTrap], &TagThresholds::default());
        assert_eq!(verdict, SpamVerdict::Reject);
    }

    #[test]
    fn override_weights_respected() {
        let mut t = TagThresholds::default();
        t.tag_weights.insert("dnsbl".into(), 10);
        let (verdict, outcomes) = evaluate_tags(&[TagSet::Dnsbl], &t);
        assert_eq!(verdict, SpamVerdict::Allow);
        assert_eq!(outcomes[0].weight, 10);
    }

    #[test]
    fn stack_crosses_discard() {
        let (verdict, _) = evaluate_tags(
            &[TagSet::Dnsbl, TagSet::Url, TagSet::Rules, TagSet::Headers],
            &TagThresholds::default(),
        );
        assert_eq!(verdict, SpamVerdict::Discard);
    }
}