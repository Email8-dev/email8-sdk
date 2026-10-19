// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Threading - the CheekyHash algorithm (normalized subject + references)
//! re-implemented on SQL.
//!
//! The legacy index property (`EmailField::Threading`, CheekyHash of the
//! normalized thread name) becomes the generated `thread_key` column; this
//! crate computes it from a parsed message so the ingest path can assign
//! threads without re-reading the store design doc.
//!
//! Design: `email8/design/sentin8-email8-store-technical-design.md` §5.

use crate::message::ParsedMessage;

/// The thread key for a message: a stable 64-bit hash of the normalized
/// subject combined with its lineage root id.
///
/// Legacy semantics (`utils::cheeky_hash`): the subject is normalized
/// (lowercased, punctuation removed, `re:` prefixes and leading
/// `[External]`-style tags stripped). The hashed id set is the message's
/// reference chain when present, else its own Message-ID - so a reply
/// and its parent land on the same key (the parent's id appears in the
/// child's references).
pub fn thread_key(msg: &ParsedMessage) -> u64 {
    let normalized_subject = normalize_subject(msg.subject().unwrap_or(""));
    let mut hasher = blake3::Hasher::new();
    hasher.update(normalized_subject.as_bytes());
    let references = msg.reference_ids();
    if references.is_empty() {
        if let Some(mid) = msg.message_id() {
            hasher.update(mid.as_bytes());
            hasher.update(&[0x1f]);
        }
    } else {
        for reference in references {
            hasher.update(reference.as_bytes());
            hasher.update(&[0x1f]); // unit separator between refs
        }
    }
    // Fold the 32-byte BLAKE3 output into the legacy-style u64 key space.
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let mut key = 0u64;
    for chunk in bytes.chunks(8) {
        let mut v = 0u64;
        for (i, b) in chunk.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        key ^= v.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    // Avoid zero (scout "no key") while keeping the space dense.
    if key == 0 {
        1
    } else {
        key
    }
}

/// Normalize a subject for threading: lowercase, strip `re:`/`fwd:`/`fw:`
/// prefix tokens (repeatedly, even when interleaved with leading bracket
/// tags) and collapse non-alphanumerics. Bracket tag text stays in the
/// normalized name (legacy semantics: `[External]` → `external`).
pub fn normalize_subject(subject: &str) -> String {
    let mut s: String = subject.trim().to_string();
    let mut tags: Vec<String> = Vec::new();
    loop {
        let lower = s.to_ascii_lowercase();
        if let Some(rest) = lower
            .strip_prefix("re:")
            .or_else(|| lower.strip_prefix("fw:"))
            .or_else(|| lower.strip_prefix("fwd:"))
        {
            s = rest.trim_start().to_string();
            continue;
        }
        // Leading `[tag]` - transparent for prefix stripping; the text
        // is re-attached so collapse keeps it as a word.
        if s.starts_with('[') {
            if let Some(end) = s.find(']') {
                let tag = s[1..end].trim().to_string();
                if !tag.is_empty() && tag.len() <= 32 {
                    tags.push(tag);
                    s = s[end + 1..].trim_start().to_string();
                    continue;
                }
            }
        }
        break;
    }
    if !tags.is_empty() {
        s = format!("{} {}", tags.join(" "), s);
    }
    let mut out = String::with_capacity(s.len());
    let mut last_was_sep = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push(' ');
            last_was_sep = true;
        }
    }
    out.trim().to_string()
}

/// Reference-set equality - duplicate detection (legacy: exact
/// reference-set equality marks the message a duplicate of an existing
/// thread member).
pub fn same_reference_set(a: &[String], b: &[String]) -> bool {
    let mut a_set = a.to_vec();
    let mut b_set = b.to_vec();
    a_set.sort();
    b_set.sort();
    a_set.dedup();
    b_set.dedup();
    a_set == b_set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_reply_chains() {
        assert_eq!(
            normalize_subject("Re: Re: FWD: Hello World!"),
            "hello world"
        );
        assert_eq!(
            normalize_subject("Re: [External] re: report"),
            "external report"
        );
    }

    #[test]
    fn same_lineage_same_key() {
        let raw_a = b"Subject: Hello\r\nMessage-ID: <a@x>\r\n\r\nbody";
        let raw_b = b"Subject: Re: Hello\r\nMessage-ID: <b@x>\r\nReferences: <a@x>\r\n\r\nbody";
        let a = ParsedMessage::parse(raw_a).unwrap();
        let b = ParsedMessage::parse(raw_b).unwrap();
        assert_eq!(thread_key(&a), thread_key(&b));
    }

    #[test]
    fn different_subjects_differ() {
        let raw_a = b"Subject: Hello\r\nMessage-ID: <a@x>\r\n\r\nbody";
        let raw_c = b"Subject: Completely other\r\nMessage-ID: <c@x>\r\n\r\nbody";
        let a = ParsedMessage::parse(raw_a).unwrap();
        let c = ParsedMessage::parse(raw_c).unwrap();
        assert_ne!(thread_key(&a), thread_key(&c));
    }

    #[test]
    fn reference_set_equality() {
        let a = vec!["x@y".to_string(), "z@w".to_string()];
        let b = vec!["z@w".to_string(), "x@y".to_string()];
        assert!(same_reference_set(&a, &b));
        assert!(!same_reference_set(&a, &["q@r".to_string()]));
    }
}
