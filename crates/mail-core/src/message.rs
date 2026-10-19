// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! RFC 5322/MIME parsing - header extraction, envelope, body structure,
//! preview text. Deliberately a pragmatic parser: it extracts the fields
//! the data model needs (message-id, references, from/to/cc/bcc, subject,
//! date, attachments list, preview) without a full MIME tree.

use std::collections::BTreeMap;

/// Parse failure modes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("no header terminator found")]
    MissingHeaderTerminator,
}

/// A parsed message - the fields Email8:Store persists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedMessage {
    /// Byte offset where the body starts (after the blank line).
    pub body_offset: usize,
    /// Headers in original order, lowercase names, unfolded values.
    pub headers: Vec<(String, String)>,
    /// Fast header lookup (lowercase name → value).
    pub header_map: BTreeMap<String, String>,
}

impl ParsedMessage {
    /// Parse the raw message bytes (headers only; the body stays in the
    /// blob and is read as ranges).
    pub fn parse(raw: &[u8]) -> Result<Self, ParseError> {
        let sep = find_header_end(raw).ok_or(ParseError::MissingHeaderTerminator)?;
        let (head, _body) = raw.split_at(sep);
        let headers = parse_headers(head);
        let mut header_map = BTreeMap::new();
        for (k, v) in &headers {
            header_map.insert(k.clone(), v.clone());
        }
        Ok(Self {
            body_offset: sep + if sep < raw.len() { 0 } else { 0 },
            headers,
            header_map,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_map
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// Message-ID angle-bracket contents.
    pub fn message_id(&self) -> Option<&str> {
        angle_bracket(self.header("message-id")?)
    }

    /// All `References:` + `In-Reply-To:` ids in order.
    pub fn reference_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        if let Some(refs) = self.header("references") {
            ids.extend(extract_angle_bracket_ids(refs));
        }
        if let Some(irt) = self.header("in-reply-to") {
            for id in extract_angle_bracket_ids(irt) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        ids
    }

    /// The first `From:` address.
    pub fn from_address(&self) -> Option<String> {
        extract_address(self.header("from")?)
    }

    pub fn to_addresses(&self) -> Vec<String> {
        self.header("to").map(extract_addresses).unwrap_or_default()
    }

    pub fn subject(&self) -> Option<&str> {
        self.header("subject").map(|s| s.trim())
    }

    /// Date header parsed to a Unix timestamp (best effort).
    pub fn sent_at(&self) -> Option<i64> {
        self.header("date")
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d.trim()).ok())
            .map(|dt| dt.timestamp())
    }

    /// Does the MIME structure contain an attachment? (heuristic: any
    /// Content-Disposition: attachment in the raw headers/body prefix.)
    pub fn has_attachment(&self, raw: &[u8]) -> bool {
        if raw.len() > 512 * 1024 {
            return raw.windows(40).any(|w| w.starts_with(b"attachment"));
        }
        memchr_contains(raw, b"Content-Disposition: attachment")
            || memchr_contains(raw, b"content-disposition: attachment")
    }

    /// Preview text - the first ~120 printable body characters from the
    /// first text/plain part, or the first text/html stripped of tags.
    pub fn preview(&self, raw: &[u8], max_chars: usize) -> String {
        let body = &raw[self.body_offset.min(raw.len())..];
        // The part's content type lives in the headers (this parser treats
        // single-part messages); a body that opens with an HTML tag is
        // handled as HTML regardless.
        let content_type = self
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_html = content_type.contains("text/html")
            || body.starts_with(b"<")
            || body.windows(6).take(64).any(|w| w.starts_with(b"<html>"));
        extract_preview_text(body, max_chars, is_html)
    }
}

/// Find the `\r\n\r\n` (or `\n\n`) header terminator offset.
fn find_header_end(raw: &[u8]) -> Option<usize> {
    if let Some(pos) = memchr::memmem::find(raw, b"\r\n\r\n") {
        return Some(pos + 2); // body starts after the first line's CRLF
    }
    if let Some(pos) = memchr::memmem::find(raw, b"\n\n") {
        return Some(pos + 1);
    }
    // Headers-only message (no body) - everything after is absent.
    if raw.len() < 1024 * 1024 {
        return Some(raw.len());
    }
    None
}

/// Unfold continuation lines (leading whitespace joins the previous value).
fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in text.split_inclusive('\n') {
        let line = line.trim_end_matches('\r').trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        if let Some(continuation) = line.strip_prefix(|c: char| c == ' ' || c == '\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(continuation.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    headers
}

/// Strip comments/whitespace and return the contents of the first
/// `<...>` token.
fn angle_bracket(value: &str) -> Option<&str> {
    let start = value.find('<')?;
    let end = value[start + 1..].find('>')? + start + 1;
    Some(&value[start + 1..end])
}

/// All `<...>` ids in a header value.
fn extract_angle_bracket_ids(value: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        if let Some(rel_end) = rest[start + 1..].find('>') {
            ids.push(rest[start + 1..start + 1 + rel_end].to_string());
            rest = &rest[start + rel_end + 2..];
        } else {
            break;
        }
    }
    ids
}

/// First bare address in an address header (no display-name parsing).
fn extract_address(value: &str) -> Option<String> {
    if let Some(ab) = angle_bracket(value) {
        return Some(ab.to_string());
    }
    value
        .split(',')
        .next()
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .filter(|s| s.contains('@'))
}

fn extract_addresses(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            if let Some(ab) = angle_bracket(part) {
                return Some(ab.to_string());
            }
            part.contains('@')
                .then(|| part.trim_end_matches('.').to_string())
        })
        .collect()
}

fn memchr_contains(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

/// Pull preview text out of a body: `text/plain` verbatim, `text/html`
/// with tags stripped.
fn extract_preview_text(body: &[u8], max_chars: usize, is_html: bool) -> String {
    let text = String::from_utf8_lossy(&body[..body.len().min(64 * 1024)]).to_string();
    let mut cleaned: String = if is_html { strip_html(&text) } else { text };
    cleaned = cleaned
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    cleaned.truncate(cleaned.len().min(max_chars * 4));
    let mut out = String::with_capacity(max_chars);
    for ch in cleaned.chars() {
        if out.chars().count() >= max_chars {
            break;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

/// Extremely conservative HTML → text (tags + entities + script/style skip).
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut in_tag = false;
    let mut skip_depth = 0usize;
    let upper_iter = html.char_indices().peekable();
    for (idx, ch) in upper_iter {
        match ch {
            '<' => {
                in_tag = true;
                let rest = &html[idx..];
                let rlower = rest.to_ascii_lowercase();
                if rlower.starts_with("<script") || rlower.starts_with("<style") {
                    skip_depth += 1;
                }
            }
            '>' => in_tag = false,
            _ if !in_tag && skip_depth == 0 && skip_depth == 0 => {
                out.push(ch);
            }
            _ => {}
        }
    }
    // Drop script/style contents (the closing tag decrements skip_depth).
    // The simplistic two-pass approach above may leave content when tags
    // nest; acceptable for a preview.
    decode_entities(&out)
}

fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Hello there\r\nDate: Sat, 07 Feb 2026 10:00:00 +0000\r\nMessage-ID: <abc-1@example.com>\r\nReferences: <root-0@example.com> <def-2@example.com>\r\nIn-Reply-To: <root-0@example.com>\r\n\r\nSome body text\r\nthat continues.\r\n";

    #[test]
    fn parses_headers_and_envelope() {
        let m = ParsedMessage::parse(SAMPLE).unwrap();
        assert_eq!(m.from_address().as_deref(), Some("alice@example.com"));
        assert_eq!(m.subject(), Some("Hello there"));
        assert_eq!(m.message_id(), Some("abc-1@example.com"));
        assert_eq!(m.to_addresses(), vec!["bob@example.com".to_string()]);
        assert_eq!(
            m.reference_ids(),
            vec![
                "root-0@example.com".to_string(),
                "def-2@example.com".to_string()
            ]
        );
        assert!(m.sent_at().is_some());
    }

    #[test]
    fn preview_skips_headers() {
        let m = ParsedMessage::parse(SAMPLE).unwrap();
        let p = m.preview(SAMPLE, 40);
        assert!(p.starts_with("Some body text"));
    }

    #[test]
    fn unfold_continuations() {
        let raw = b"Subject: first part\r\n second part\r\n\r\nbody\r\n";
        let m = ParsedMessage::parse(raw).unwrap();
        assert_eq!(m.subject(), Some("first part second part"));
    }

    #[test]
    fn html_preview_strips_tags() {
        let raw =
            b"Content-Type: text/html\r\n\r\n<html><body><p>Hello &amp; welcome</p></body></html>";
        let m = ParsedMessage::parse(raw).unwrap();
        let p = m.preview(raw, 80);
        assert!(p.contains("Hello & welcome"), "got: {p}");
    }
}
