// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Sieve interpreter — executes a compiled script against a mail,
//! collecting actions. No I/O; vacation state and mailbox-name
//! resolution belong to the caller.

use crate::compiler::{AddressPart, Comparator, EnvelopePart, Matcher, Script, Statement, Test};

/// The message-under-test (already parsed by the caller).
#[derive(Debug, Clone)]
pub struct Mail {
    pub from: String,
    pub to: Vec<String>,
    /// (lowercase-name, unfolded value) — from the RFC 5322 headers.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    FileInto(String),
    Redirect(String),
    Reject(String),
    Vacation { reason: String, days: u32 },
    Keep,
    Discard,
    Stop,
}

#[derive(Debug, Clone)]
pub struct InterpreterError(pub String);

impl std::fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sieve: {}", self.0)
    }
}
impl std::error::Error for InterpreterError {}

/// Run a compiled script → ordered actions. Implicit keep at the end
/// unless the script explicitly handles the message (fileinto/redirect/
/// discard/reject/stop/keep appear in the output).
pub fn run(script: &Script, mail: &Mail) -> Result<Vec<Action>, InterpreterError> {
    let mut ctx = Run { mail, actions: Vec::new(), stopped: false };
    ctx.statements(&script.statements)?;
    // RFC 5228 §2.7.3.1: implicit keep unless any fileinto/redirect/
    // discard/reject/keep/vacation handled it or stop was hit.
    let handled = ctx.actions.iter().any(|a| {
        matches!(
            a,
            Action::FileInto(_)
                | Action::Redirect(_)
                | Action::Reject(_)
                | Action::Keep
                | Action::Discard
                | Action::Vacation { .. }
                | Action::Stop
        )
    });
    if !handled {
        ctx.actions.push(Action::Keep);
    }
    Ok(ctx.actions)
}

struct Run<'a> {
    mail: &'a Mail,
    actions: Vec<Action>,
    stopped: bool,
}

impl<'a> Run<'a> {
    fn statements(&mut self, stmts: &[Statement]) -> Result<(), InterpreterError> {
        for s in stmts {
            if self.stopped {
                break;
            }
            match s {
                Statement::FileInto(folder) => self.actions.push(Action::FileInto(folder.clone())),
                Statement::Redirect(addr) => self.actions.push(Action::Redirect(addr.clone())),
                Statement::Reject(reason) => {
                    self.actions.push(Action::Reject(reason.clone()));
                    self.actions.push(Action::Stop);
                    self.stopped = true;
                }
                Statement::Vacation { reason, days } => {
                    self.actions.push(Action::Vacation { reason: reason.clone(), days: *days });
                }
                Statement::Keep => self.actions.push(Action::Keep),
                Statement::Discard => self.actions.push(Action::Discard),
                Statement::Stop => {
                    self.actions.push(Action::Stop);
                    self.stopped = true;
                }
                Statement::If { test, then, els } => {
                    if self.test(test)? {
                        self.statements(then)?;
                    } else {
                        self.statements(els)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn test(&mut self, t: &Test) -> Result<bool, InterpreterError> {
        Ok(match t {
            Test::True => true,
            Test::False => false,
            Test::Not(inner) => !self.test(inner)?,
            Test::AnyOf(list) => {
                for inner in list {
                    if self.test(inner)? {
                        return Ok(true);
                    }
                }
                false
            }
            Test::AllOf(list) => {
                for inner in list {
                    if !self.test(inner)? {
                        return Ok(false);
                    }
                }
                true
            }
            Test::Exists(names) => names.iter().all(|n| {
                self.mail
                    .headers
                    .iter()
                    .any(|(hn, _)| hn.eq_ignore_ascii_case(n))
            }),
            Test::Size { over, under } => {
                over.map(|o| self.mail.size > o).unwrap_or(true)
                    && under.map(|u| self.mail.size < u).unwrap_or(true)
            }
            Test::Header { matcher, comparator, names, keys } => {
                let mut hit = false;
                'outer: for key in keys {
                    for name in names {
                        for (hn, hv) in &self.mail.headers {
                            if !hn.eq_ignore_ascii_case(name) {
                                continue;
                            }
                            if value_matches(*matcher, *comparator, hv, key) {
                                hit = true;
                                break 'outer;
                            }
                        }
                    }
                }
                hit
            }
            Test::Address { part, matcher, names, keys } => {
                // Address test reuses the header values but only the
                // addr-spec part(s).
                let mut hit = false;
                'outer: for key in keys {
                    for name in names {
                        for (hn, hv) in &self.mail.headers {
                            if !hn.eq_ignore_ascii_case(name) {
                                continue;
                            }
                            let addr = extract_addr_spec(hv);
                            let candidate = match part {
                                AddressPart::Local => addr.split('@').next().unwrap_or("").to_string(),
                                AddressPart::Domain => addr.rsplit('@').next().unwrap_or("").to_string(),
                                AddressPart::All => addr,
                            };
                            if value_matches(*matcher, Comparator::AsciiCaseMap, &candidate, key) {
                                hit = true;
                                break 'outer;
                            }
                        }
                    }
                }
                hit
            }
            Test::Body { matcher, keys } => {
                let text = String::from_utf8_lossy(&self.mail.body).to_ascii_lowercase();
                keys.iter().any(|k| match matcher {
                    Matcher::Contains => text.contains(&k.to_ascii_lowercase()),
                    Matcher::Is => text.trim() == k.trim(),
                    Matcher::Matches => glob_match(k, &text),
                })
            }
            Test::Envelope { part, matcher, keys } => {
                let candidate = match part {
                    EnvelopePart::From => self.mail.from.clone(),
                    EnvelopePart::To => self.mail.to.first().cloned().unwrap_or_default(),
                };
                keys.iter().any(|k| match matcher {
                    Matcher::Contains => candidate.to_ascii_lowercase().contains(&k.to_ascii_lowercase()),
                    Matcher::Is => candidate.eq_ignore_ascii_case(k),
                    Matcher::Matches => glob_match(k, &candidate),
                })
            }
        })
    }
}

fn extract_addr_spec(value: &str) -> String {
    if let Some(start) = value.find('<') {
        if let Some(end) = value[start..].find('>') {
            return value[start + 1..start + end].to_string();
        }
    }
    value.trim().to_string()
}

fn value_matches(matcher: Matcher, comparator: Comparator, value: &str, key: &str) -> bool {
    match matcher {
        Matcher::Is => match comparator {
            Comparator::AsciiCaseMap => value.trim().eq_ignore_ascii_case(key.trim()),
            Comparator::AsciiNumeric => {
                let vn: i64 = value.trim().parse().unwrap_or(i64::MIN);
                let kn: i64 = key.trim().parse().unwrap_or(i64::MIN);
                vn == kn
            }
        },
        Matcher::Contains => value.to_ascii_lowercase().contains(&key.to_ascii_lowercase()),
        // RFC 5228 §2.7.1 — `*` and `?` glob over the whole value.
        Matcher::Matches => glob_match(key, value),
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    // Convert to regex, escaping everything but * and ?.
    let mut re = String::with_capacity(pattern.len() * 2);
    re.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => {
                if regex::escape(&c.to_string()) == c.to_string() {
                    re.push(c);
                } else {
                    re.push_str(&regex::escape(&c.to_string()));
                }
            }
        }
    }
    re.push('$');
    match regex::Regex::new(&re) {
        Ok(r) => r.is_match(value),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{self};

    fn script(src: &str) -> compiler::Script {
        compiler::compile(src).expect("script must compile")
    }

    fn mail() -> Mail {
        Mail {
            from: "alice@example.com".into(),
            to: vec!["bob@example.net".into()],
            headers: vec![
                ("from".into(), "Alice <alice@Example.COM>".into()),
                ("to".into(), "bob@example.net".into()),
                ("subject".into(), "[list] Hello".into()),
                ("x-priority".into(), "1".into()),
            ],
            body: b"Buy widgets now!".to_vec(),
            size: 512,
        }
    }

    // ── Test combinators ──────────────────────────────────────────────

    #[test]
    fn anyof_short_circuits_and_allof_requires_all() {
        let s = script(
            r#"if anyof (header :is "subject" "nope", header :contains "subject" "[list]") { fileinto "A"; }"#,
        );
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("A".into())]);

        let s = script(
            r#"if allof (header :is "subject" "nope", header :contains "subject" "[list]") { fileinto "A"; }"#,
        );
        // allof fails → implicit keep.
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);
    }

    #[test]
    fn not_negates() {
        let s = script(r#"if not header :contains "subject" "[list]" { discard; }"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);
    }

    #[test]
    fn exists_requires_every_header() {
        let s = script(r#"if exists ["subject", "x-nonexistent"] { discard; }"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);

        let s = script(r#"if exists ["subject", "X-PRIORITY"] { discard; }"#);
        // Header names are case-insensitive.
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Discard]);
    }

    // ── Matchers ──────────────────────────────────────────────────────

    #[test]
    fn header_matches_glob() {
        let s = script(r#"if header :matches "subject" "[*] Hell?" { fileinto "A"; }"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("A".into())]);
    }

    #[test]
    fn header_is_is_case_insensitive() {
        let s = script(r#"if header :is "SUBJECT" "[LIST] hello" { keep; stop; }"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep, Action::Stop]);
    }

    #[test]
    fn numeric_comparator_compares_values_not_strings() {
        // ascii-numeric: "9" < "10" numerically (string compare would say 9 > 10).
        let m = Mail { size: 5, ..mail() };
        let s = script(
            r#"require ["comparator-i;ascii-numeric"];
if header :comparator "i;ascii-numeric" :is "x-priority" "1" { discard; }"#,
        );
        assert_eq!(run(&s, &m).unwrap(), vec![Action::Discard]);
    }

    // ── Address tests ─────────────────────────────────────────────────

    #[test]
    fn address_localpart_and_domain_extraction() {
        let s = script(
            r#"if address :localpart :is "from" "alice" { fileinto "Local"; }"#,
        );
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("Local".into())]);

        let s = script(
            r#"if address :domain :is "from" "example.com" { fileinto "Dom"; }"#,
        );
        // Display-name + <> form is unwrapped to the addr-spec.
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("Dom".into())]);
    }

    // ── Body / envelope / size ────────────────────────────────────────

    #[test]
    fn body_contains_case_insensitive() {
        let s = script(r#"if body :contains "WIDGETS" { reject "no"; }"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Reject("no".into()), Action::Stop]);
    }

    #[test]
    fn envelope_to_matches() {
        let s = script(
            r#"require ["envelope"];
if envelope :to :matches "*@example.net" { redirect "x@y.z"; }"#,
        );
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Redirect("x@y.z".into())]);
    }

    #[test]
    fn size_under_matches() {
        let m = Mail { size: 100, ..mail() };
        let s = script(r#"if size :under 200 { discard; }"#);
        assert_eq!(run(&s, &m).unwrap(), vec![Action::Discard]);

        let s = script(r#"if size :under 50 { discard; }"#);
        assert_eq!(run(&s, &m).unwrap(), vec![Action::Keep]);
    }

    // ── Action semantics ──────────────────────────────────────────────

    #[test]
    fn implicit_keep_only_when_unhandled() {
        let s = script("keep;");
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);

        let s = script(r#"fileinto "A";"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("A".into())]);

        // discard handles the message (no implicit keep).
        let s = script("discard;");
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Discard]);

        let s = script(r#"vacation :days 2 "off";"#);
        assert_eq!(
            run(&s, &mail()).unwrap(),
            vec![Action::Vacation { reason: "off".into(), days: 2 }]
        );
    }

    #[test]
    fn stop_halts_subsequent_statements() {
        let s = script("stop;\nkeep;\ndiscard;");
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Stop]);
    }

    #[test]
    fn reject_implies_stop() {
        let s = script(r#"reject "no"; keep;"#);
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Reject("no".into()), Action::Stop]);
    }

    #[test]
    fn else_branch_taken_when_if_false() {
        let s = script(
            r#"if false { fileinto "A"; } else { fileinto "B"; }"#,
        );
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::FileInto("B".into())]);
    }

    #[test]
    fn glob_special_chars_escaped() {
        // A `.` in the pattern must not act as a regex wildcard.
        let s = script(r#"if header :matches "subject" "a.c" { discard; }"#);
        // Value is "[list] Hello" — "a.c" must NOT match.
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);
    }

    #[test]
    fn address_part_matches_with_contains() {
        let s = script(
            r#"if address :domain :contains "to" "EXAMPLE" { keep; }"#,
        );
        // Address tests always use ascii-casemap.
        assert_eq!(run(&s, &mail()).unwrap(), vec![Action::Keep]);
    }
}