// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! MIME tree walker (story 2.1) - splits a raw RFC 2045 message into its
//! part tree without decoding transport encodings at walk time (offsets
//! point at the raw bytes; `decode_part` handles base64/quoted-printable
//! when text extraction needs it).
//!
//! The walker is deliberately conservative: it never panics on malformed
//! input, treats `message/rfc822` and all non-multipart leaves as opaque
//! payloads, and falls back to a single-part tree when boundaries are
//! missing or unterminated.

use base64::Engine;

/// One MIME part (leaf or container) located in the raw message bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MimePart {
    /// Lowercased `Content-Type` media type (`text/plain`); empty when
    /// the part carries no Content-Type (RFC 2045 §5.2 default:
    /// text/plain us-ascii).
    pub content_type: String,
    /// Lowercased charset param (`utf-8`), empty when absent.
    pub charset: String,
    /// Multipart boundary param (multipart/* containers only).
    pub boundary: Option<String>,
    /// Lowercased `Content-Transfer-Encoding` (`base64`,
    /// `quoted-printable`, `7bit`…), `7bit` when absent.
    pub transfer_encoding: String,
    /// Byte offset of the part body (after its part headers).
    pub body_offset: usize,
    /// Byte length of the part body (bounded by the parent boundary).
    pub body_len: usize,
    /// `Content-Disposition` value (`inline`/`attachment`), lowercase.
    pub disposition: Option<String>,
    /// `filename`/`name` param (attachment naming).
    pub filename: Option<String>,
    /// Child parts (multipart containers only).
    pub children: Vec<MimePart>,
}

impl MimePart {
    /// True when this part is a multipart container.
    pub fn is_multipart(&self) -> bool {
        self.boundary.is_some()
    }

    /// True when the part is an attachment (Content-Disposition:
    /// attachment, or a non-(text|multipart|message) top-level type with
    /// a filename).
    pub fn is_attachment(&self) -> bool {
        if self.disposition.as_deref() == Some("attachment") {
            return true;
        }
        let top = self.content_type.split('/').next().unwrap_or("");
        !matches!(top, "text" | "multipart" | "message" | "") && self.filename.is_some()
    }
}

/// Walk the full MIME tree of a raw message, depth-first flattened
/// (containers before children).
pub fn walk_parts(raw: &[u8]) -> Vec<MimePart> {
    let Some(sep) = find_blank_line(raw) else {
        return Vec::new();
    };
    let (head, body) = raw.split_at(sep);
    let headers = parse_part_headers(head);
    let root = parse_part(&headers, body, sep);
    if root.content_type.is_empty() && root.children.is_empty() {
        return Vec::new();
    }
    flatten(&root)
}

/// The first `text/plain` (or any text) part's bytes, transport-decoded.
pub fn first_text_body(raw: &[u8], parts: &[MimePart]) -> Option<Vec<u8>> {
    for p in parts {
        if p.content_type == "text/plain" {
            return Some(decode_part(raw, p));
        }
    }
    for p in parts {
        if p.content_type.starts_with("text/") {
            return Some(decode_part(raw, p));
        }
    }
    // No text part found: fall back to the first leaf body.
    parts.first().map(|p| decode_part(raw, p))
}

/// All `text/calendar` parts, transport-decoded - iMIP (story 4.6).
pub fn calendar_bodies(raw: &[u8], parts: &[MimePart]) -> Vec<Vec<u8>> {
    parts
        .iter()
        .filter(|p| p.content_type == "text/calendar")
        .map(|p| decode_part(raw, p))
        .collect()
}

/// Transport-decode one part's body bytes (base64/quoted-printable).
pub fn decode_part(raw: &[u8], p: &MimePart) -> Vec<u8> {
    let body = &raw[p.body_offset..(p.body_offset + p.body_len).min(raw.len())];
    match p.transfer_encoding.as_str() {
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(
                body.iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| body.to_vec()),
        "quoted-printable" => decode_qp(body),
        _ => body.to_vec(),
    }
}

fn flatten(part: &MimePart) -> Vec<MimePart> {
    let mut out = vec![part.clone()];
    for c in &part.children {
        out.extend(flatten(c));
    }
    out
}

fn decode_qp(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let text = String::from_utf8_lossy(body);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '=' {
            out.extend(c.to_string().as_bytes());
            continue;
        }
        match (chars.next(), chars.next()) {
            (Some('\r'), Some('\n')) => {} // soft line break
            (Some(a), Some(b)) => {
                let hex = format!("{a}{b}");
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    out.push(byte);
                }
            }
            _ => out.push(b'='),
        }
    }
    out
}

fn find_blank_line(raw: &[u8]) -> Option<usize> {
    if let Some(p) = memchr::memmem::find(raw, b"\r\n\r\n") {
        return Some(p + 4);
    }
    memchr::memmem::find(raw, b"\n\n").map(|p| p + 2)
}

/// Parse one part: headers up to the blank line, then either recurse into
/// multipart children (split on the boundary) or take the whole body.
/// `base` is the absolute byte offset of `body[0]` within `raw` - all
/// offsets stored on the part (and its children) are absolute.
fn parse_part(headers: &[(String, String)], body: &[u8], base: usize) -> MimePart {
    let mut part = MimePart {
        transfer_encoding: "7bit".to_string(),
        body_offset: base,
        body_len: body.len(),
        ..Default::default()
    };
    for (name, value) in headers {
        match name.as_str() {
            "content-type" => {
                let (ctype, params) = parse_params(value);
                part.content_type = ctype;
                for (k, v) in params {
                    match k.as_str() {
                        "charset" => part.charset = v.to_ascii_lowercase(),
                        "boundary" => part.boundary = Some(v),
                        "name" if part.filename.is_none() => part.filename = Some(v),
                        _ => {}
                    }
                }
            }
            "content-transfer-encoding" => {
                part.transfer_encoding = value
                    .split(';')
                    .next()
                    .unwrap_or("7bit")
                    .trim()
                    .to_ascii_lowercase();
            }
            "content-disposition" => {
                let (disp, params) = parse_params(value);
                part.disposition = Some(disp);
                for (k, v) in params {
                    if k == "filename" {
                        part.filename = Some(v);
                    }
                }
            }
            _ => {}
        }
    }

    // Multipart container: split the body on the boundary and recurse.
    if let Some(boundary) = &part.boundary {
        for (seg_start, seg_end) in split_boundary(body, boundary) {
            let seg = &body[seg_start..seg_end];
            let Some(part_sep) = find_blank_line(seg) else {
                continue; // preamble junk with no headers
            };
            let (seg_head, seg_body) = seg.split_at(part_sep);
            let child_headers = parse_part_headers(seg_head);
            part.children.push(parse_part(
                &child_headers,
                seg_body,
                base + seg_start + part_sep,
            ));
        }
        // Container body itself is not payload - mark empty.
        part.body_len = 0;
    }
    part
}

/// `type/subtype; param="value"; k=v` → (type, params).
fn parse_params(value: &str) -> (String, Vec<(String, String)>) {
    let mut segs = value.split(';');
    let ctype = segs.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut params = Vec::new();
    for p in segs {
        let p = p.trim();
        if let Some((k, v)) = p.split_once('=') {
            let v = v.trim().trim_matches('"');
            params.push((k.trim().to_ascii_lowercase(), v.to_string()));
        }
    }
    (ctype, params)
}

/// Split a multipart body on `--boundary` lines. Returns (start, end)
/// byte windows for each inter-boundary segment (excludes the boundary
/// lines themselves and the closing `--boundary--`).
fn split_boundary(body: &[u8], boundary: &str) -> Vec<(usize, usize)> {
    let marker = format!("--{boundary}");
    let marker_bytes = marker.as_bytes();
    let mut segments = Vec::new();
    let mut line_start = 0usize;
    let mut current_start: Option<usize> = None;
    while line_start < body.len() {
        let line_end = body[line_start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|p| line_start + p)
            .unwrap_or(body.len());
        let line = &body[line_start..line_end];
        let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
        if trimmed.starts_with(marker_bytes) {
            if let Some(start) = current_start.take() {
                segments.push((start, line_start));
            }
            // Closing boundary (`--boundary--`)? Stop.
            if trimmed[marker_bytes.len()..].starts_with(b"--") {
                break;
            }
            current_start = Some(line_end + 1);
        }
        line_start = line_end + 1;
    }
    if let Some(start) = current_start {
        // Unterminated final part - take the rest.
        segments.push((start, body.len()));
    }
    segments
}

/// Part header block parser (lowercase names, unfolded continuations).
fn parse_part_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split_inclusive('\n') {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple 2-part multipart fixture.
    fn multipart_raw() -> Vec<u8> {
        b"From: a@b.c\r\n\
          Subject: hi\r\n\
          Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n\
          \r\n\
          preamble junk\r\n\
          --XYZ\r\n\
          Content-Type: text/plain; charset=UTF-8\r\n\
          \r\n\
          hello body\r\n\
          --XYZ\r\n\
          Content-Type: application/pdf; name=\"doc.pdf\"\r\n\
          Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
          Content-Transfer-Encoding: base64\r\n\
          \r\n\
          aGVsbG8=\r\n\
          --XYZ--\r\n\
          epilogue\r\n"
            .to_vec()
    }

    #[test]
    fn multipart_two_children_flattened() {
        let parts = walk_parts(&multipart_raw());
        assert_eq!(parts.len(), 3, "container + 2 leaves");
        assert_eq!(parts[0].content_type, "multipart/mixed");
        assert!(parts[0].is_multipart());
        assert_eq!(parts[0].body_len, 0, "container body is not payload");
        assert_eq!(parts[1].content_type, "text/plain");
        assert_eq!(parts[1].charset, "utf-8");
        assert_eq!(parts[2].content_type, "application/pdf");
    }

    #[test]
    fn first_text_body_decodes_plain_part() {
        let raw = multipart_raw();
        let parts = walk_parts(&raw);
        // Body window runs to the next boundary line - trailing CRLF kept.
        assert_eq!(first_text_body(&raw, &parts).unwrap(), b"hello body\r\n");
    }

    #[test]
    fn base64_part_transport_decoded() {
        let raw = multipart_raw();
        let parts = walk_parts(&raw);
        // aGVsbG8= → "hello"
        let pdf = parts
            .iter()
            .find(|p| p.content_type == "application/pdf")
            .unwrap();
        assert_eq!(decode_part(&raw, pdf), b"hello");
    }

    #[test]
    fn attachment_detection_via_disposition_and_type() {
        let raw = multipart_raw();
        let parts = walk_parts(&raw);
        let pdf = parts
            .iter()
            .find(|p| p.content_type == "application/pdf")
            .unwrap();
        assert!(pdf.is_attachment());
        assert_eq!(pdf.filename.as_deref(), Some("report.pdf"));
        let txt = parts
            .iter()
            .find(|p| p.content_type == "text/plain")
            .unwrap();
        assert!(!txt.is_attachment());
    }

    #[test]
    fn quoted_printable_decoded() {
        let raw = b"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9 =\r\nnext\r\n";
        let parts = walk_parts(raw);
        assert_eq!(parts.len(), 1);
        let body = decode_part(raw, &parts[0]);
        // C3 A9 = é; soft break (=\r\n) removed; final CRLF kept.
        assert_eq!(body, "café next\r\n".as_bytes());
    }

    #[test]
    fn no_headers_body_returns_empty_tree() {
        // A blank line immediately at offset 0 with no Content-Type.
        let parts = walk_parts(b"just body, no headers\r\n");
        assert!(parts.is_empty());
    }

    #[test]
    fn unterminated_boundary_takes_rest_of_body() {
        let raw = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\npart one never closed";
        let parts = walk_parts(raw);
        assert_eq!(parts.len(), 2);
        let leaf = &parts[1];
        assert_eq!(leaf.content_type, "text/plain");
        assert_eq!(decode_part(raw, leaf), b"part one never closed");
    }

    #[test]
    fn nested_multipart_recursed() {
        let raw = b"Content-Type: multipart/mixed; boundary=OUT\r\n\r\n\
          --OUT\r\n\
          Content-Type: multipart/alternative; boundary=IN\r\n\
          \r\n\
          --IN\r\n\
          Content-Type: text/plain\r\n\
          \r\n\
          plain\r\n\
          --IN\r\n\
          Content-Type: text/html\r\n\
          \r\n\
          <b>html</b>\r\n\
          --IN--\r\n\
          --OUT--\r\n";
        let parts = walk_parts(raw);
        let types: Vec<&str> = parts.iter().map(|p| p.content_type.as_str()).collect();
        assert_eq!(
            types,
            vec![
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "text/html"
            ]
        );
    }

    #[test]
    fn calendar_bodies_collected() {
        let raw = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n\
          --B\r\n\
          Content-Type: text/plain\r\n\
          \r\n\
          body text\r\n\
          --B\r\n\
          Content-Type: text/calendar; method=REQUEST\r\n\
          \r\n\
          BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n\
          --B--\r\n";
        let parts = walk_parts(raw);
        let cals = calendar_bodies(raw, &parts);
        assert_eq!(cals.len(), 1);
        assert!(String::from_utf8_lossy(&cals[0]).contains("BEGIN:VCALENDAR"));
    }

    #[test]
    fn header_continuation_unfolded() {
        let raw = b"Content-Type: multipart/mixed;\r\n boundary=Q\r\n\r\n--Q\r\nContent-Type: text/plain\r\n\r\nx\r\n--Q--\r\n";
        let parts = walk_parts(raw);
        assert_eq!(parts[0].content_type, "multipart/mixed");
        assert_eq!(parts[0].boundary.as_deref(), Some("Q"));
    }

    #[test]
    fn never_panics_on_garbage() {
        // Random hostile bytes must not panic (conservative walker).
        let junk: Vec<u8> = (0..u8::MAX).cycle().take(4096).collect();
        let _ = walk_parts(&junk);
        let _ = walk_parts(b"");
        let _ = walk_parts(b"\r\n\r\n\r\n");
    }

    #[test]
    fn part_offsets_absolute() {
        let raw = multipart_raw();
        let parts = walk_parts(&raw);
        for p in &parts {
            // Every body window must be in-bounds (offset math sanity).
            assert!(p.body_offset + p.body_len <= raw.len());
        }
        let txt = parts
            .iter()
            .find(|p| p.content_type == "text/plain")
            .unwrap();
        assert_eq!(
            &raw[txt.body_offset..txt.body_offset + txt.body_len],
            b"hello body\r\n"
        );
    }
}
