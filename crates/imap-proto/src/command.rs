// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Typed IMAP command model — the ops the Email8:Access server implements
//! in P1 plus the FETCH/STORE/SEARCH/LIST argument grammars.

use std::collections::BTreeSet;

/// A complete client command: `{tag} {op}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCommand {
    pub tag: String,
    pub op: Op,
}

/// Core op set (P1 + the high-frequency P3 ops). Extensions map their
/// arguments into these variants; unimplemented ops answer BAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Capability,
    Noop,
    Logout,
    StartTls,
    Authenticate { mechanism: String, initial: Option<String> },
    Sasl { token: String },
    Login { username: String, password: String },
    Enable { capabilities: Vec<String> },
    Id { payload: Option<String> },
    Select { mailbox: String },
    Examine { mailbox: String },
    Create { mailbox: String },
    Delete { mailbox: String },
    Rename { from: String, to: String },
    Subscribe { mailbox: String },
    Unsubscribe { mailbox: String },
    List { reference: String, pattern: String, options: Vec<String>, extended: bool },
    Lsub { reference: String, pattern: String },
    Status { mailbox: String, items: Vec<StatusItem> },
    Append {
        mailbox: String,
        flags: Vec<String>,
        date_time: Option<String>,
        literal_size: usize,
    },
    Check,
    Close,
    Unselect,
    Expunge { uids: Option<Vec<String>> },
    Search { criteria: SearchCriteria },
    Fetch { sequence: SequenceSet, items: Vec<FetchItem>, uid: bool },
    Store {
        sequence: SequenceSet,
        items: Vec<StoreItem>,
        silent: bool,
        uid: bool,
        unchanged_since: Option<u64>,
    },
    Copy { sequence: SequenceSet, mailbox: String, uid: bool },
    Move { sequence: SequenceSet, mailbox: String, uid: bool },
    /// RFC 5256 SORT — sort keys + search criteria (the search filters
    /// the candidate set, the keys define order).
    Sort {
        keys: Vec<String>,
        criteria: SearchCriteria,
        uid: bool,
    },
    /// RFC 5256 THREAD — REFERENCES | ORDEREDSUBJECT algorithm.
    Thread { algorithm: String, criteria: SearchCriteria, uid: bool },
    Idle,
    Done,
    /// Anything else — answered BAD without a typed model.
    Unsupported { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
    Size,
    Deleted,
    HighestModSeq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    Flags,
    Uid,
    InternalDate,
    Rfc822Size,
    Rfc822Header,
    Rfc822,
    Envelope,
    BodyStructure { extended: bool },
    Body { section: String, partial: Option<(u64, u64)>, peek: bool },
    ModSeq,
    Preview { lazy: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreItem {
    Flags(BTreeSet<String>),
    Add(BTreeSet<String>),
    Remove(BTreeSet<String>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchCriteria {
    pub all: bool,
    pub uids: Vec<u64>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub text: Option<String>,
    pub seen: Option<bool>,
    pub answered: Option<bool>,
    pub flagged: Option<bool>,
    pub deleted: Option<bool>,
    pub draft: Option<bool>,
    pub older_than_secs: Option<u64>,
    pub larger: Option<u64>,
    pub smaller: Option<u64>,
}

/// IMAP sequence-set (`1:3,5,*`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequenceSet(pub Vec<SequenceRange>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceRange {
    pub start: u64,
    pub end: Option<u64>, // None = `*`
}

impl SequenceSet {
    pub fn contains(&self, value: u64, max: u64) -> bool {
        self.0.iter().any(|r| {
            let start = r.start;
            let end = r.end.unwrap_or(max);
            let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
            value >= lo && value <= hi
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Parse a complete command line into a [`ClientCommand`]. The receiver
/// pre-strips the tag and handles LITERAL continuations; `parse` sees a
/// complete argument slice.
pub fn parse(line: &str) -> Option<ClientCommand> {
    let mut parts = line.splitn(2, ' ');
    let tag = parts.next()?.to_string();
    if tag.is_empty() || tag.len() > 64 {
        return None;
    }
    let rest = parts.next().unwrap_or("");
    let op = parse_op(rest)?;
    Some(ClientCommand { tag, op })
}

fn parse_op(rest: &str) -> Option<Op> {
    let (verb, args) = match rest.find(' ') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    match verb.to_ascii_uppercase().as_str() {
        "CAPABILITY" => Some(Op::Capability),
        "NOOP" => Some(Op::Noop),
        "LOGOUT" => Some(Op::Logout),
        "STARTTLS" => Some(Op::StartTls),
        "IDLE" => Some(Op::Idle),
        "DONE" => Some(Op::Done),
        "CHECK" => Some(Op::Check),
        "CLOSE" => Some(Op::Close),
        "UNSELECT" => Some(Op::Unselect),
        "AUTHENTICATE" => {
            let mut p = args.splitn(2, ' ');
            let mechanism = p.next()?.to_ascii_uppercase();
            let initial = p.next().map(|s| s.to_string());
            Some(Op::Authenticate { mechanism, initial })
        }
        "LOGIN" => {
            let mut p = args.splitn(3, ' ');
            let username = unquote(p.next()?)?;
            let password = unquote(p.next()?)?;
            Some(Op::Login { username, password })
        }
        "ENABLE" => Some(Op::Enable { capabilities: args.split_whitespace().map(|s| s.to_string()).collect() }),
        "ID" => Some(Op::Id { payload: Some(args.to_string()) }),
        "SELECT" => Some(Op::Select { mailbox: unquote(args)? }),
        "EXAMINE" => Some(Op::Examine { mailbox: unquote(args)? }),
        "CREATE" => Some(Op::Create { mailbox: unquote(args)? }),
        "DELETE" => Some(Op::Delete { mailbox: unquote(args)? }),
        "SUBSCRIBE" => Some(Op::Subscribe { mailbox: unquote(args)? }),
        "UNSUBSCRIBE" => Some(Op::Unsubscribe { mailbox: unquote(args)? }),
        "RENAME" => {
            let mut p = args.splitn(2, ' ');
            let from = unquote(p.next()?)?;
            let to = unquote(p.next()?)?;
            Some(Op::Rename { from, to })
        }
        "LIST" => {
            // Possibly LIST (REF) "pattern" or plain LIST ref pattern
            let extended = args.starts_with('(');
            let stripped = if extended {
                args.split_once(')')?.1.trim_start()
            } else {
                args
            };
            let mut p = stripped.splitn(2, ' ');
            let reference = unquote(p.next().unwrap_or(""))?;
            let pattern = unquote(p.next().unwrap_or(""))?;
            Some(Op::List { reference, pattern, options: vec![], extended })
        }
        "LSUB" => {
            let mut p = args.splitn(2, ' ');
            let reference = unquote(p.next().unwrap_or(""))?;
            let pattern = unquote(p.next().unwrap_or(""))?;
            Some(Op::Lsub { reference, pattern })
        }
        "STATUS" => {
            // STATUS "mailbox" (items)
            let (mailbox, items_str) = args.split_once('(')?;
            let mailbox = unquote(mailbox.trim())?;
            let items_str = items_str.trim_end_matches(')');
            let mut items = Vec::new();
            for tok in items_str.split_whitespace() {
                items.push(match tok.to_ascii_uppercase().as_str() {
                    "MESSAGES" => StatusItem::Messages,
                    "RECENT" => StatusItem::Recent,
                    "UIDNEXT" => StatusItem::UidNext,
                    "UIDVALIDITY" => StatusItem::UidValidity,
                    "UNSEEN" => StatusItem::Unseen,
                    "SIZE" => StatusItem::Size,
                    "DELETED" => StatusItem::Deleted,
                    "HIGHESTMODSEQ" => StatusItem::HighestModSeq,
                    _ => return None,
                });
            }
            Some(Op::Status { mailbox, items })
        }
        "APPEND" => {
            // APPEND "mailbox" [flags] [date] {size}
            let mut p = args.splitn(2, ' ');
            let mailbox = unquote(p.next()?)?;
            let rest = p.next().unwrap_or("");
            let mut flags = Vec::new();
            let mut date_time = None;
            let mut work = rest.trim();
            if let Some(f) = work.strip_prefix('(') {
                let (inner, after) = f.split_once(')')?;
                flags = inner.split_whitespace().map(|s| s.to_string()).collect();
                work = after.trim();
            }
            if work.starts_with('"') {
                let end = work[1..].find('"')? + 1;
                date_time = Some(work[..=end].to_string());
                work = work[end + 1..].trim();
            }
            let literal_spec = work.strip_prefix('{')?.strip_suffix('}')?;
            let literal_size: usize =
                literal_spec.strip_suffix('+').unwrap_or(literal_spec).parse().ok()?;
            Some(Op::Append { mailbox, flags, date_time, literal_size })
        }
        "EXPUNGE" => Some(Op::Expunge { uids: None }),
        "SORT" => parse_sort(args, false),
        "THREAD" => parse_thread(args, false),
        "UID" => {
            // UID <op> ... — dispatch on the sub-op with UID-mode semantics.
            let sub_args = args;
            let (sub, sub_args) = match sub_args.find(' ') {
                Some(pos) => (&sub_args[..pos], &sub_args[pos + 1..]),
                None => (sub_args, ""),
            };
            match sub.to_ascii_uppercase().as_str() {
                "EXPUNGE" => Some(Op::Expunge { uids: Some(sub_args.split(',').map(|s| s.to_string()).collect()) }),
                "FETCH" => parse_fetch(sub_args, true),
                "STORE" => parse_store(sub_args, true),
                "COPY" => {
                    let mut p = sub_args.splitn(2, ' ');
                    let sequence = parse_sequence(p.next()?)?;
                    let mailbox = unquote(p.next()?)?;
                    Some(Op::Copy { sequence, mailbox, uid: true })
                }
                "MOVE" => {
                    let mut p = sub_args.splitn(2, ' ');
                    let sequence = parse_sequence(p.next()?)?;
                    let mailbox = unquote(p.next()?)?;
                    Some(Op::Move { sequence, mailbox, uid: true })
                }
                "SORT" => parse_sort(sub_args, true),
                "THREAD" => parse_thread(sub_args, true),
                _ => None,
            }
        }
        "FETCH" => parse_fetch(args, false),
        "STORE" => parse_store(args, false),
        "COPY" => {
            let mut p = args.splitn(2, ' ');
            let sequence = parse_sequence(p.next()?)?;
            let mailbox = unquote(p.next()?)?;
            Some(Op::Copy { sequence, mailbox, uid: false })
        }
        "MOVE" => {
            let mut p = args.splitn(2, ' ');
            let sequence = parse_sequence(p.next()?)?;
            let mailbox = unquote(p.next()?)?;
            Some(Op::Move { sequence, mailbox, uid: false })
        }
        "SEARCH" => parse_search(args),
        _ => Some(Op::Unsupported { name: verb.to_string() }),
    }
}

fn parse_fetch(args: &str, uid: bool) -> Option<Op> {
    let mut p = args.splitn(2, ' ');
    let sequence = parse_sequence(p.next()?)?;
    let items_str = p.next().unwrap_or("ALL").trim();
    let items = parse_fetch_items(items_str)?;
    Some(Op::Fetch { sequence, items, uid })
}

fn parse_fetch_items(spec: &str) -> Option<Vec<FetchItem>> {
    let spec = spec.trim();
    let mut items = Vec::new();
    if spec.eq_ignore_ascii_case("ALL") {
        items.push(FetchItem::Flags);
        items.push(FetchItem::InternalDate);
        items.push(FetchItem::Rfc822Size);
        items.push(FetchItem::Envelope);
        return Some(items);
    }
    if spec.eq_ignore_ascii_case("FAST") {
        items.push(FetchItem::Flags);
        items.push(FetchItem::InternalDate);
        items.push(FetchItem::Rfc822Size);
        return Some(items);
    }
    if spec.eq_ignore_ascii_case("FULL") {
        items.push(FetchItem::Flags);
        items.push(FetchItem::InternalDate);
        items.push(FetchItem::Rfc822Size);
        items.push(FetchItem::Envelope);
        items.push(FetchItem::BodyStructure { extended: false });
        return Some(items);
    }
    // Either a paren list or a single atom.
    let inner = spec.strip_prefix('(').map(|s| s.strip_suffix(')').unwrap_or(s)).unwrap_or(spec);
    let mut rest = inner;
    while !rest.is_empty() {
        rest = rest.trim_start();
        let tok_upper = rest.to_ascii_uppercase();
        if let Some(_rem) = tok_upper.strip_prefix("BODY.PEEK[") {
            let close = rest.find(']')?;
            let section = rest["BODY.PEEK[".len()..close].to_string();
            let after = &rest[close + 1..];
            let (partial, consumed) = if let Some(stripped) = after.strip_prefix('<') {
                let end = stripped.find('>')?;
                let spec = &stripped[..end];
                let mut it = spec.splitn(2, '.');
                let start: u64 = it.next()?.parse().ok()?;
                let len: u64 = it.next()?.parse().ok()?;
                (Some((start, len)), end + 2)
            } else {
                (None, 0)
            };
            items.push(FetchItem::Body { section, partial, peek: true });
            rest = &after[consumed..];
            continue;
        }
        if let Some(_rem) = tok_upper.strip_prefix("BODY[") {
            let close = rest.find(']')?;
            let section = rest["BODY[".len()..close].to_string();
            let after = &rest[close + 1..];
            let (partial, consumed) = if let Some(stripped) = after.strip_prefix('<') {
                let end = stripped.find('>')?;
                let spec = &stripped[..end];
                let mut it = spec.splitn(2, '.');
                let start: u64 = it.next()?.parse().ok()?;
                let len: u64 = it.next()?.parse().ok()?;
                (Some((start, len)), end + 2)
            } else {
                (None, 0)
            };
            items.push(FetchItem::Body { section, partial, peek: false });
            rest = &after[consumed..];
            continue;
        }
        // Plain atom (FLAGS, UID, RFC822.SIZE, BODYSTRUCTURE, ...)
        let end = rest.find(|c: char| c.is_whitespace() || c == '(').unwrap_or(rest.len());
        let tok = &rest[..end];
        let upper = tok.to_ascii_uppercase();
        match upper.as_str() {
            "FLAGS" => items.push(FetchItem::Flags),
            "UID" => items.push(FetchItem::Uid),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
            "RFC822.HEADER" => items.push(FetchItem::Rfc822Header),
            "RFC822" => items.push(FetchItem::Rfc822),
            "ENVELOPE" => items.push(FetchItem::Envelope),
            "BODYSTRUCTURE" => items.push(FetchItem::BodyStructure { extended: true }),
            "BODY" => items.push(FetchItem::BodyStructure { extended: false }),
            "MODSEQ" => items.push(FetchItem::ModSeq),
            "PREVIEW" => items.push(FetchItem::Preview { lazy: false }),
            _ => return None,
        }
        rest = &rest[end..];
    }
    Some(items)
}

fn parse_store(args: &str, uid: bool) -> Option<Op> {
    let mut p = args.splitn(2, ' ');
    let sequence = parse_sequence(p.next()?)?;
    let rest = p.next()?.trim();
    let (unchanged_since, rest) = if let Some(stripped) = rest.strip_prefix('(') {
        let end = stripped.find(')')?;
        let inner = &stripped[..end];
        let val = inner.strip_prefix("UNCHANGEDSINCE ")?.trim().parse().ok()?;
        (Some(val), stripped[end + 1..].trim_start())
    } else {
        (None, rest)
    };
    // Item name: `+FLAGS[.SILENT]` / `-FLAGS[.SILENT]` / `FLAGS[.SILENT]`
    // — the `.SILENT` suffix is part of the item name, so split on the
    // first whitespace and inspect the token.
    let (token, tail) = match rest.find(char::is_whitespace) {
        Some(pos) => (&rest[..pos], rest[pos..].trim_start()),
        None => (rest, ""),
    };
    let silent = token.ends_with(".SILENT");
    let token = token.strip_suffix(".SILENT").unwrap_or(token);
    let (action, flags_str): (fn(BTreeSet<String>) -> StoreItem, &str) = match token.strip_prefix('+') {
        Some(_) => (StoreItem::Add, tail),
        None => match token.strip_prefix('-') {
            Some(_) => (StoreItem::Remove, tail),
            None => (StoreItem::Flags, tail),
        },
    };
    // Flags may be parenthesized: `(\Seen $label)` — unwrap, then split.
    let flags_str = flags_str.trim();
    let flags_str = flags_str
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(flags_str);
    let flags: BTreeSet<String> =
        flags_str.trim().split_whitespace().map(|f| f.to_string()).collect();
    Some(Op::Store {
        sequence,
        items: vec![action(flags)],
        silent,
        uid,
        unchanged_since,
    })
}

/// RFC 5256 SORT parse: `SORT (keys) charset criteria`.
fn parse_sort(args: &str, uid: bool) -> Option<Op> {
    let trimmed = args.trim();
    let rest = trimmed.strip_prefix('(')?;
    let close = rest.find(')')?;
    let keys: Vec<String> = rest[..close]
        .split_whitespace()
        .map(|k| k.trim_start_matches('-').to_ascii_uppercase())
        .collect();
    if keys.is_empty() {
        return None;
    }
    // charset + criteria (charset typically US-ASCII or UTF-8; the
    // criteria rest is the standard SEARCH set).
    let after = rest[close + 1..].trim();
    let mut it = after.splitn(2, ' ');
    let _charset = it.next()?;
    let criteria = parse_criteria(it.next().unwrap_or("ALL"))?;
    Some(Op::Sort { keys, criteria, uid })
}

/// RFC 5256 THREAD parse: `THREAD REFERENCES|ORDEREDSUBJECT charset crit`.
fn parse_thread(args: &str, uid: bool) -> Option<Op> {
    let mut it = args.trim().splitn(3, ' ');
    let algorithm = it.next()?.to_ascii_uppercase();
    if algorithm != "REFERENCES" && algorithm != "ORDEREDSUBJECT" {
        return None;
    }
    let _charset = it.next()?;
    let criteria = parse_criteria(it.next().unwrap_or("ALL"))?;
    Some(Op::Thread { algorithm, criteria, uid })
}

fn parse_search(args: &str) -> Option<Op> {
    Some(Op::Search { criteria: parse_criteria(args)? })
}

/// Parse the shared SEARCH criteria grammar (also the SORT/THREAD
/// filtering part).
fn parse_criteria(args: &str) -> Option<SearchCriteria> {
    let mut crit = SearchCriteria::default();
    let mut toks = args.split_whitespace().peekable();
    while let Some(tok) = toks.next() {
        match tok.to_ascii_uppercase().as_str() {
            "ALL" => crit.all = true,
            "FROM" => crit.from = Some(toks.next()?.trim_matches('"').to_string()),
            "TO" => crit.to = Some(toks.next()?.trim_matches('"').to_string()),
            "SUBJECT" => crit.subject = Some(toks.next()?.trim_matches('"').to_string()),
            "BODY" => crit.body = Some(toks.next()?.trim_matches('"').to_string()),
            "TEXT" => crit.text = Some(toks.next()?.trim_matches('"').to_string()),
            "SEEN" => crit.seen = Some(true),
            "UNSEEN" => crit.seen = Some(false),
            "ANSWERED" => crit.answered = Some(true),
            "UNANSWERED" => crit.answered = Some(false),
            "FLAGGED" => crit.flagged = Some(true),
            "UNFLAGGED" => crit.flagged = Some(false),
            "DELETED" => crit.deleted = Some(true),
            "UNDELETED" => crit.deleted = Some(false),
            "DRAFT" => crit.draft = Some(true),
            "UNDRAFT" => crit.draft = Some(false),
            "LARGER" => crit.larger = Some(toks.next()?.parse().ok()?),
            "SMALLER" => crit.smaller = Some(toks.next()?.parse().ok()?),
            "UID" => {
                let set = parse_sequence(toks.next()?)?;
                crit.uids = set.0.iter().map(|r| r.start).collect();
            }
            _ => {
                // Bare sequence set or a date — treat a numeric token as a
                // sequence match; ignore unknowns conservatively.
                if tok.chars().all(|c| c.is_ascii_digit() || c == '*' || c == ',' || c == ':') {
                    // Sequence sets in SEARCH are position-based; the Access
                    // server maps them. Keep the raw start values.
                    if let Ok(v) = tok.parse::<u64>() {
                        crit.uids.push(v);
                    }
                }
            }
        }
    }
    Some(crit)
}

fn parse_sequence(spec: &str) -> Option<SequenceSet> {
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once(':') {
            Some((a, b)) => {
                let start: u64 = a.parse().ok()?;
                let end = if b == "*" { None } else { Some(b.parse().ok()?) };
                ranges.push(SequenceRange { start, end });
            }
            None => {
                let start: u64 = part.parse().ok()?;
                ranges.push(SequenceRange { start, end: Some(start) });
            }
        }
    }
    if ranges.is_empty() {
        return None;
    }
    Some(SequenceSet(ranges))
}

/// Strip surrounding quotes (or return as-is for atoms).
fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"') {
        let end = inner.find('"')?;
        return Some(inner[..end].to_string());
    }
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login() {
        let c = parse("a1 LOGIN alice password").unwrap();
        match c.op {
            Op::Login { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "password");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_select_quoted() {
        let c = parse("a2 SELECT \"INBOX\"").unwrap();
        assert_eq!(c.op, Op::Select { mailbox: "INBOX".into() });
    }

    #[test]
    fn parses_fetch_body_peek_partial() {
        let c = parse("a3 FETCH 1:3 (UID FLAGS BODY.PEEK[]<0.2048>)").unwrap();
        match c.op {
            Op::Fetch { sequence, items, uid } => {
                assert!(!uid);
                assert!(sequence.contains(1, 3));
                assert!(sequence.contains(3, 3));
                assert!(items.iter().any(|i| matches!(i, FetchItem::Body { peek: true, partial: Some((0, 2048)), .. })));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_uid_store_silent() {
        let c = parse("a4 UID STORE 5 +FLAGS.SILENT (\\Seen $label)").unwrap();
        match c.op {
            Op::Store { items, silent, uid, sequence, .. } => {
                assert!(silent && uid);
                assert!(sequence.contains(5, 10));
                match &items[0] {
                    StoreItem::Add(flags) => {
                        assert!(flags.contains("\\Seen"));
                        assert!(flags.contains("$label"));
                    }
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_status_items() {
        let c = parse("a5 STATUS \"Sent\" (MESSAGES UIDNEXT UIDVALIDITY)").unwrap();
        match c.op {
            Op::Status { mailbox, items } => {
                assert_eq!(mailbox, "Sent");
                assert_eq!(items.len(), 3);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_append_literal() {
        let c = parse("a6 APPEND \"Drafts\" (\\Draft) {310+}").unwrap();
        match c.op {
            Op::Append { mailbox, literal_size, flags, .. } => {
                assert_eq!(mailbox, "Drafts");
                assert_eq!(literal_size, 310);
                assert_eq!(flags, vec!["\\Draft".to_string()]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_search() {
        let c = parse("a7 SEARCH FROM \"hamid\" UNSEEN").unwrap();
        match c.op {
            Op::Search { criteria } => {
                assert_eq!(criteria.from.as_deref(), Some("hamid"));
                assert_eq!(criteria.seen, Some(false));
            }
            other => panic!("{other:?}"),
        }
    }
}