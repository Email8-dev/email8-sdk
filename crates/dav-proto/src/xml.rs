// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Minimal XML toolkit for DAV bodies - parse into a node tree (name,
//! attrs, children, text), then query with `child("ns:name")`; build
//! with a small writer that tracks namespaces. CDATA and processing
//! instructions are skipped; entity refs are decoded.

use std::collections::BTreeMap;

/// A parsed element.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlNode {
    pub name: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<XmlNode>,
    pub text: String,
}

/// Escape XML text/attribute content.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Parse a DAV XML body into its root node. Namespaced elements are
/// reported with the prefix intact (`D:propfind`). Returns None for
/// empty/whitespace bodies (allowed by RFC 4918 - empty PROPFIND means
/// "allprop").
pub fn parse(input: &[u8]) -> Option<XmlNode> {
    let text = String::from_utf8_lossy(input);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    skip_prologue(trimmed, &mut pos);
    parse_element(trimmed, &mut pos)
}

fn skip_prologue(s: &str, pos: &mut usize) {
    loop {
        let rest = &s[*pos..];
        if rest.starts_with("<?") {
            if let Some(end) = rest.find("?>") {
                *pos += end + 2;
                continue;
            }
        }
        if rest.starts_with("<!--") {
            if let Some(end) = rest.find("-->") {
                *pos += end + 3;
                continue;
            }
        }
        if rest.starts_with("<!") {
            // DOCTYPE etc. - skip to '>'
            if let Some(end) = rest.find('>') {
                *pos += end + 1;
                continue;
            }
        }
        break;
    }
}

fn parse_element(s: &str, pos: &mut usize) -> Option<XmlNode> {
    let rest = &s[*pos..];
    let rest = rest.trim_start();
    *pos = s.len() - rest.len();
    if !rest.starts_with('<') {
        return None;
    }
    // Find the tag name.
    let tag_end = rest.find('>')?;
    let inner = &rest[1..tag_end];
    let self_closing = inner.trim_end().ends_with('/');
    let inner_trim = inner.trim_end_matches('/');
    let mut parts = inner_trim.splitn(2, char::is_whitespace);
    let name = parts.next()?.trim().to_string();
    let mut attrs = BTreeMap::new();
    if let Some(attr_text) = parts.next() {
        // Parse `k="v"` / `k='v'` pairs (quoted values may contain
        // spaces - scan pairwise, not whitespace-split).
        let bytes = attr_text.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            // Skip whitespace.
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            // Key up to '='.
            let key_start = i;
            while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let key = &attr_text[key_start..i];
            if i < bytes.len() && bytes[i] == b'=' {
                i += 1;
                let quote = bytes.get(i).copied();
                let value = match quote {
                    Some(b'"') | Some(b'\'') => {
                        let q = quote.unwrap();
                        i += 1;
                        let v_start = i;
                        while i < bytes.len() && bytes[i] != q {
                            i += 1;
                        }
                        let v = &attr_text[v_start..i];
                        if i < bytes.len() {
                            i += 1; // closing quote
                        }
                        v.to_string()
                    }
                    _ => {
                        // Unquoted value - up to whitespace.
                        let v_start = i;
                        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                            i += 1;
                        }
                        attr_text[v_start..i].to_string()
                    }
                };
                attrs.insert(key.to_string(), value);
            } else if !key.is_empty() {
                // Valueless attribute - record as empty.
                attrs.insert(key.to_string(), String::new());
            }
        }
    }
    *pos += tag_end + 1;
    if self_closing {
        return Some(XmlNode {
            name,
            attrs,
            children: Vec::new(),
            text: String::new(),
        });
    }
    // Children/text until the closing tag.
    let mut children = Vec::new();
    let mut text = String::new();
    let close = format!("</{name}");
    loop {
        let rest = &s[*pos..];
        if rest.is_empty() {
            return Some(XmlNode {
                name,
                attrs,
                children,
                text,
            }); // unclosed - tolerate
        }
        if rest.trim_start().starts_with(&close) {
            let end = rest.find('>')?;
            *pos += end + 1;
            return Some(XmlNode {
                name,
                attrs,
                children,
                text,
            });
        }
        if rest.trim_start().starts_with('<') {
            let before = rest.trim_start();
            *pos = s.len() - before.len();
            if let Some(child) = parse_element(s, pos) {
                children.push(child);
            }
            continue;
        }
        // Text run.
        let next_tag = rest.find('<').unwrap_or(rest.len());
        text.push_str(&decode_entities(&rest[..next_tag]));
        *pos += next_tag;
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let semi = s[i..].find(';').map(|p| i + p);
        let Some(semi) = semi else {
            out.push('&');
            continue;
        };
        let entity = &s[i + 1..semi];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => {
                if let Ok(cp) = u32::from_str_radix(&e[2..], 16) {
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                    }
                }
            }
            e if e.starts_with('#') => {
                if let Ok(cp) = e[1..].parse::<u32>() {
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                    }
                }
            }
            _ => out.push_str(&s[i..semi + 1]),
        }
        // Advance past the entity.
        for (j, _) in chars.by_ref() {
            if j >= semi {
                break;
            }
        }
    }
    out
}

impl XmlNode {
    /// First child matching `name` - exact match, or local-name match
    /// when the query has no prefix (accepts any prefix like `D:`).
    pub fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| {
            if c.name == name {
                return true;
            }
            // Query "prop" matches "D:prop" - but query "D:prop" only
            // matches "D:prop" exactly.
            if !name.contains(':') {
                return c.name.rsplit(':').next() == Some(name) && c.name.contains(':');
            }
            false
        })
    }

    /// All children matching `name` (same rule as `child`).
    pub fn children_named(&self, name: &str) -> Vec<&XmlNode> {
        self.children
            .iter()
            .filter(|c| {
                if c.name == name {
                    return true;
                }
                if !name.contains(':') {
                    return c.name.rsplit(':').next() == Some(name) && c.name.contains(':');
                }
                false
            })
            .collect()
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(|s| s.as_str())
    }

    pub fn text_of(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.text.trim().to_string())
    }
}

/// The XML builder - writes one root with children.
pub struct Xml {
    out: String,
    /// Declared namespaces on the root (prefix → URI).
    ns: Vec<(String, String)>,
}

impl Default for Xml {
    fn default() -> Self {
        Self::new()
    }
}

impl Xml {
    pub fn new() -> Self {
        Self {
            out: String::new(),
            ns: Vec::new(),
        }
    }

    pub fn with_ns(mut self, prefix: &str, uri: &str) -> Self {
        self.ns.push((prefix.to_string(), uri.to_string()));
        self
    }

    /// Open the root element.
    pub fn open(&mut self, name: &str) {
        self.out
            .push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<");
        self.out.push_str(name);
        for (prefix, uri) in &self.ns {
            self.out
                .push_str(&format!(" xmlns:{prefix}=\"{}\"", escape(uri)));
        }
        self.out.push('>');
    }

    pub fn close(&mut self, name: &str) {
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }

    /// A leaf element with text content.
    pub fn leaf(&mut self, name: &str, text: &str) {
        self.out
            .push_str(&format!("<{name}>{}</{name}>", escape(text)));
    }

    /// An empty leaf (`<name/>`).
    pub fn empty(&mut self, name: &str) {
        self.out.push_str(&format!("<{name}/>"));
    }

    /// Open a child element (pair with `end`).
    pub fn start(&mut self, name: &str) {
        self.out.push_str(&format!("<{name}>"));
    }

    pub fn end(&mut self, name: &str) {
        self.out.push_str(&format!("</{name}>"));
    }

    pub fn finish(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_propfind() {
        let body = br#"<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getetag/>
    <D:resourcetype/>
  </D:prop>
</D:propfind>"#;
        let root = parse(body).unwrap();
        assert_eq!(root.name, "D:propfind");
        let prop = root.child("prop").unwrap();
        assert_eq!(prop.children_named("getetag").len(), 1);
        assert_eq!(prop.children_named("resourcetype").len(), 1);
    }

    #[test]
    fn parses_text_and_entities() {
        let body = br#"<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
  <filter>
    <comp-filter name="VEVENT">
      <time-range start="20260903T000000Z"/>
    </comp-filter>
  </filter>
</calendar-query>"#;
        let root = parse(body).unwrap();
        let tr = root
            .child("filter")
            .and_then(|f| f.child("comp-filter"))
            .and_then(|c| c.child("time-range"))
            .unwrap();
        assert_eq!(tr.attr("start"), Some("20260903T000000Z"));
    }

    #[test]
    fn builds_multistatus() {
        let mut x = Xml::new().with_ns("D", "DAV:");
        x.open("D:multistatus");
        x.start("D:response");
        x.leaf("D:href", "/dav/cal/42/");
        x.start("D:propstat");
        x.leaf("D:status", "HTTP/1.1 200 OK");
        x.end("D:propstat");
        x.end("D:response");
        x.close("D:multistatus");
        let s = x.finish();
        assert!(s.contains("xmlns:D=\"DAV:\""));
        assert!(s.contains("<D:href>/dav/cal/42/</D:href>"));
    }

    #[test]
    fn escapes_text() {
        assert_eq!(escape("a<b>&\"c\""), "a&lt;b&gt;&amp;&quot;c&quot;");
    }

    #[test]
    fn empty_body_is_none() {
        assert!(parse(b"   ").is_none());
        assert!(parse(b"").is_none());
    }
}
