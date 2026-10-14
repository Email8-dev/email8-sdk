// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! IMAP response builders — greeting, capabilities, tagged/untagged lines,
//! literal-safe quoting.

/// Quote a string for IMAP wire output (RFC 9051 §4.3).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// An untagged response line (`* ...`).
pub fn untagged(data: impl AsRef<str>) -> String {
    format!("* {}\r\n", data.as_ref())
}

/// A tagged completion (`{tag} OK ...`).
pub fn tagged_ok(tag: &str, data: impl AsRef<str>) -> String {
    format!("{tag} OK {}\r\n", data.as_ref())
}

pub fn tagged_no(tag: &str, data: impl AsRef<str>) -> String {
    format!("{tag} NO {}\r\n", data.as_ref())
}

pub fn tagged_bad(tag: &str, data: impl AsRef<str>) -> String {
    format!("{tag} BAD {}\r\n", data.as_ref())
}

/// Server greeting (`* OK [CAPABILITY ...] ... ready`).
pub fn greeting(hostname: &str, capabilities: &[&str]) -> String {
    format!(
        "* OK [CAPABILITY {}] {} Email8 IMAP at your service.\r\n",
        capabilities.join(" "),
        hostname
    )
}

/// Capability list (P1 subset — grows with Epic 4.1).
pub const CAPABILITIES_PRE_AUTH: &[&str] = &[
    "IMAP4rev2",
    "IMAP4rev1",
    "ENABLE",
    "SASL-IR",
    "LITERAL+",
    "ID",
    "UTF8=ACCEPT",
    "AUTH=XOAUTH2",
    "AUTH=OAUTHBEARER",
    "STARTTLS",
];

pub const CAPABILITIES_POST_AUTH: &[&str] = &[
    "IMAP4rev2",
    "IMAP4rev1",
    "ENABLE",
    "IDLE",
    "NAMESPACE",
    "CHILDREN",
    "MULTIAPPEND",
    "BINARY",
    "UNSELECT",
    "UIDPLUS",
    "ESEARCH",
    "WITHIN",
    "SEARCHRES",
    "SORT",
    "LIST-EXTENDED",
    "LIST-STATUS",
    "SPECIAL-USE",
    "CREATE-SPECIAL-USE",
    "MOVE",
    "CONDSTORE",
    "QRESYNC",
    "STATUS=SIZE",
    "OBJECTID",
    "PREVIEW",
    "QUOTA",
    "UIDONLY",
    "LITERAL+",
    "UTF8=ACCEPT",
];

/// `* CAPABILITY` line.
pub fn capability_line(caps: &[&str]) -> String {
    untagged(format!("CAPABILITY {}", caps.join(" ")))
}

/// `* LIST` / `* LSUB` line with attributes and delimiter.
pub fn list_line(attrs: &[&str], delimiter: &str, mailbox: &str) -> String {
    let attr_str = if attrs.is_empty() { "()".to_string() } else { format!("({})", attrs.join(" ")) };
    untagged(format!("LIST {} {} {}", attr_str, quote(delimiter), quote(mailbox)))
}

pub fn status_line(mailbox_id: uuid::Uuid, items: &[(&str, i64)]) -> String {
    let body = items.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(" ");
    untagged(format!("STATUS [EMAIL8-ID {mailbox_id}] ({body})"))
}

/// `* OK [UIDVALIDITY n] [UIDNEXT m]` SELECT preamble pieces.
pub fn select_ok(uidvalidity: i64, uid_next: i64, exists: i64) -> String {
    let mut s = String::new();
    s.push_str(&untagged(format!("{exists} EXISTS")));
    s.push_str(&untagged(format!("OK [UIDVALIDITY {uidvalidity}] UIDs valid")));
    s.push_str(&untagged(format!("OK [UIDNEXT {uid_next}] Predicted next UID")));
    s
}

/// `* SEARCH` result line.
pub fn search_line(ids: &[i64]) -> String {
    if ids.is_empty() {
        untagged("SEARCH")
    } else {
        let joined = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
        untagged(format!("SEARCH {joined}"))
    }
}

/// FETCH response with a quoted-string item.
pub fn fetch_item(seq: i64, item: impl AsRef<str>, value: impl AsRef<str>) -> String {
    untagged(format!("{seq} FETCH ({})", format_item_pair(item, value)))
}

fn format_item_pair(item: impl AsRef<str>, value: impl AsRef<str>) -> String {
    format!("{} {}", item.as_ref(), value.as_ref())
}

/// FETCH response with a literal body (RFC 9051 §4.1.2).
pub fn fetch_literal(seq: i64, item: impl AsRef<str>, data: &[u8]) -> String {
    let mut s = String::new();
    s.push_str(&format!("* {seq} FETCH ({} {{{}}}\r\n", item.as_ref(), data.len()));
    s.push_str(&String::from_utf8_lossy(data));
    s.push_str(")\r\n");
    s
}

/// IMAP flag names ↔ keyword mapping (`\Seen`, `\Flagged`, `\Answered`,
/// `\Draft`, `\Deleted`, plus `$` keywords).
pub mod flags {
    pub const SEEN: &str = "\\Seen";
    pub const FLAGGED: &str = "\\Flagged";
    pub const ANSWERED: &str = "\\Answered";
    pub const DRAFT: &str = "\\Draft";
    pub const DELETED: &str = "\\Deleted";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn tagged_and_untagged() {
        assert_eq!(tagged_ok("A1", "Done"), "A1 OK Done\r\n");
        assert_eq!(untagged("22 EXISTS"), "* 22 EXISTS\r\n");
    }

    #[test]
    fn search_line_empty() {
        assert_eq!(search_line(&[]), "* SEARCH\r\n");
        assert_eq!(search_line(&[1, 4]), "* SEARCH 1 4\r\n");
    }
}