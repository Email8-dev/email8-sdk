// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 DAV wire helpers - a minimal, robust XML toolkit for
//! CalDAV/CardDAV/WebDAV bodies: `propfind`/`proppatch`/`report`
//! request parsing (no external XML crate - DAV bodies are small and
//! shallow; a hand-rolled scanner avoids the dependency), response
//! building (multistatus + status rows), ETag/lock-token utilities,
//! `Depth` header parsing.
//!
//! The DAV *handlers* (PROPFIND dispatch, reports, scheduling) live in
//! Email8:Access; this crate only deals with wire shapes.

pub mod xml;

pub use xml::{escape, Xml, XmlNode};

/// The `Depth` request header (RFC 4918 §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    Zero,
    One,
    Infinity,
}

impl Depth {
    pub fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim()) {
            Some("0") => Depth::Zero,
            Some("1") => Depth::One,
            _ => Depth::Infinity,
        }
    }
}

/// A strong ETag (`"..."` quoted form).
pub fn etag_for(resource_type: &str, version: i64) -> String {
    format!("\"{resource_type}-{version}\"")
}

/// Validate an `If-Match`/`If-None-Match` header against the current
/// ETag. `None` header → matches (precondition absent).
pub fn if_match_ok(header: Option<&str>, current: Option<&str>) -> bool {
    let Some(h) = header else { return true };
    if h.trim() == "*" {
        return current.is_some();
    }
    current.map(|c| c == h.trim()).unwrap_or(false)
}

/// RFC 2058 lock token URIs.
pub fn new_lock_token() -> String {
    format!("opaquelocktoken:{}", uuid_like())
}

fn uuid_like() -> String {
    // Avoid a uuid dep: chrono entropy + pid mixed into 32 hex chars.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mix = nanos ^ (pid.rotate_left(64));
    format!("{:032x}", mix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_parse() {
        assert_eq!(Depth::parse(Some("0")), Depth::Zero);
        assert_eq!(Depth::parse(Some("1")), Depth::One);
        assert_eq!(Depth::parse(Some("infinity")), Depth::Infinity);
        assert_eq!(Depth::parse(None), Depth::Infinity);
    }

    #[test]
    fn etag_and_if_match() {
        let etag = etag_for("event", 42);
        assert!(etag.starts_with('"') && etag.ends_with('"'));
        assert!(if_match_ok(None, Some(&etag)));
        assert!(if_match_ok(Some(&etag), Some(&etag)));
        assert!(!if_match_ok(Some("\"other\""), Some(&etag)));
        assert!(if_match_ok(Some("*"), Some(&etag)));
        assert!(!if_match_ok(Some("*"), None));
    }

    #[test]
    fn lock_tokens_are_unique() {
        let a = new_lock_token();
        let b = new_lock_token();
        assert_ne!(a, b);
        assert!(a.starts_with("opaquelocktoken:"));
    }
}
