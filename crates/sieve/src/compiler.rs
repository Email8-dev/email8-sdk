// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Sieve compiler — RFC 5228 grammar subset: require, if/elsif/else,
//! test lists (anyof/allof/not), header/address/exists/size/body/
//! envelope/true/false tests, actions fileinto/redirect/reject/keep/
//! stop/discard/vacation, string + numeric literals, tagged args
//! (:is/:contains/:matches/:over/:under/:comparator).

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Error0 {
    UnexpectedToken { line: usize, token: String },
    UnknownRequire(String),
    UnclosedBlock { line: usize },
    MissingArguments { line: usize, what: String },
}

impl fmt::Display for Error0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error0::UnexpectedToken { line, token } => write!(f, "line {line}: unexpected {token}"),
            Error0::UnknownRequire(s) => write!(f, "unknown require '{s}'"),
            Error0::UnclosedBlock { line } => write!(f, "line {line}: unclosed block"),
            Error0::MissingArguments { line, what } => write!(f, "line {line}: expected {what}"),
        }
    }
}

impl std::error::Error for Error0 {}

pub type CompilerError = Error0;

/// A compiled script — validated, zero unbound requirements.
#[derive(Debug, Clone)]
pub struct Script {
    pub requires: Vec<String>,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    FileInto(String),
    Redirect(String),
    Reject(String),
    Vacation {
        reason: String,
        days: u32,
    },
    Keep,
    Discard,
    Stop,
    If {
        test: Test,
        then: Vec<Statement>,
        els: Vec<Statement>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Test {
    True,
    False,
    Not(Box<Test>),
    AnyOf(Vec<Test>),
    AllOf(Vec<Test>),
    Header {
        matcher: Matcher,
        comparator: Comparator,
        names: Vec<String>,
        keys: Vec<String>,
    },
    Address {
        part: AddressPart,
        matcher: Matcher,
        names: Vec<String>,
        keys: Vec<String>,
    },
    Exists(Vec<String>),
    Size {
        over: Option<u64>,
        under: Option<u64>,
    },
    Body {
        matcher: Matcher,
        keys: Vec<String>,
    },
    Envelope {
        part: EnvelopePart,
        matcher: Matcher,
        keys: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matcher {
    Is,
    Contains,
    Matches,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparator {
    AsciiCaseMap,
    AsciiNumeric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPart {
    Local,
    Domain,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopePart {
    From,
    To,
}

const KNOWN_REQUIRES: &[&str] = &[
    "fileinto",
    "redirect",
    "reject",
    "vacation",
    "envelope",
    "comparator-i;ascii-casemap",
    "comparator-i;ascii-numeric",
    "body",
    "imap4flags",
    "variables",
    "copy",
    "notify",
];

/// Compile a script source. Errors on unknown requires (the untrusted
/// compiler must refuse scripts the interpreter can't honor).
pub fn compile(source: &str) -> Result<Script, CompilerError> {
    let tokens = tokenize(source)?;
    let mut parser = Parser { tokens, pos: 0 };
    let mut requires = Vec::new();
    let mut statements = Vec::new();
    while let Some((_, token)) = parser.peek() {
        let is_require = matches!(token, Tok::Word(w) if w == "require");
        if is_require {
            parser.advance();
            let list = parser.parse_string_list()?;
            for r in list {
                if !KNOWN_REQUIRES.contains(&r.as_str()) {
                    return Err(Error0::UnknownRequire(r));
                }
                requires.push(r);
            }
        } else {
            let mut req_snapshot = requires.clone();
            statements = parser.parse_statements(&mut req_snapshot)?;
            // A require appearing after statements is still collected.
            requires = req_snapshot;
        }
    }
    Ok(Script {
        requires,
        statements,
    })
}

// ── Tokenizer ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Number(u64),
    Tag(String),
    BraceOpen,
    BraceClose,
    Semicolon,
    Comma,
    LParen,
    RParen,
    BracketOpen,
    BracketClose,
}

fn tokenize(source: &str) -> Result<Vec<(usize, Tok)>, Error0> {
    let mut out = Vec::new();
    let mut chars = source.chars().peekable();
    let mut line = 1usize;
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            ' ' | '\t' | '\r' => {}
            '#' => {
                // comment to end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut closed = false;
                loop {
                    let Some(c) = chars.next() else { break };
                    if c == '\n' {
                        line += 1;
                    }
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(Error0::UnclosedBlock { line });
                }
            }
            '{' => out.push((line, Tok::BraceOpen)),
            '}' => out.push((line, Tok::BraceClose)),
            ';' => out.push((line, Tok::Semicolon)),
            ',' => out.push((line, Tok::Comma)),
            '(' => out.push((line, Tok::LParen)),
            ')' => out.push((line, Tok::RParen)),
            '[' => out.push((line, Tok::BracketOpen)),
            ']' => out.push((line, Tok::BracketClose)),
            ':' => {
                let mut word = String::new();
                loop {
                    match chars.peek() {
                        Some(&n) if n.is_alphanumeric() => {
                            word.push(n);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                out.push((line, Tok::Tag(word)));
            }
            '"' => {
                let mut s = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(esc) = chars.next() {
                                s.push(esc);
                            }
                        }
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\n' => return Err(Error0::UnclosedBlock { line }),
                        _ => s.push(c),
                    }
                }
                if !closed {
                    return Err(Error0::UnclosedBlock { line });
                }
                out.push((line, Tok::Quoted(s)));
            }
            c if c.is_ascii_digit() => {
                let mut num = String::new();
                num.push(c);
                loop {
                    match chars.peek() {
                        Some(&n) if n.is_ascii_digit() => {
                            num.push(n);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                out.push((line, Tok::Number(num.parse().unwrap_or(0))));
            }
            c if c.is_alphanumeric() || c == '_' => {
                let mut word = String::new();
                word.push(c);
                // Peek-based continuation: take_while would swallow the
                // first non-matching char.
                loop {
                    match chars.peek() {
                        Some(&n) if n.is_alphanumeric() || n == '_' || n == '-' => {
                            word.push(n);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                out.push((line, Tok::Word(word)));
            }
            other => {
                return Err(Error0::UnexpectedToken {
                    line,
                    token: other.to_string(),
                });
            }
        }
    }
    Ok(out)
}

// ── Parser ────────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<(usize, Tok)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<(usize, &Tok)> {
        self.tokens.get(self.pos).map(|(l, t)| (*l, t))
    }

    fn advance(&mut self) -> Option<(usize, Tok)> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect_word(&mut self, what: &str) -> Result<String, Error0> {
        match self.advance() {
            Some((_, Tok::Word(w))) if !w.is_empty() => Ok(w),
            Some((line, t)) => Err(Error0::UnexpectedToken {
                line,
                token: format!("{t:?} ({what})"),
            }),
            None => Err(Error0::MissingArguments {
                line: 0,
                what: what.into(),
            }),
        }
    }

    fn expect_quoted(&mut self, what: &str) -> Result<String, Error0> {
        match self.advance() {
            Some((_, Tok::Quoted(s))) => Ok(s),
            Some((line, t)) => Err(Error0::UnexpectedToken {
                line,
                token: format!("{t:?} ({what})"),
            }),
            None => Err(Error0::MissingArguments {
                line: 0,
                what: what.into(),
            }),
        }
    }

    fn parse_string_list(&mut self) -> Result<Vec<String>, Error0> {
        let mut out = Vec::new();
        match self.advance() {
            Some((_, Tok::BracketOpen)) => loop {
                match self.advance() {
                    Some((_, Tok::Quoted(s))) => out.push(s),
                    Some((line, t)) => {
                        return Err(Error0::UnexpectedToken {
                            line,
                            token: format!("{t:?}"),
                        })
                    }
                    None => return Err(Error0::UnclosedBlock { line: 0 }),
                }
                match self.advance() {
                    Some((_, Tok::Comma)) => continue,
                    Some((_, Tok::BracketClose)) => break,
                    Some((line, t)) => {
                        return Err(Error0::UnexpectedToken {
                            line,
                            token: format!("{t:?}"),
                        })
                    }
                    None => return Err(Error0::UnclosedBlock { line: 0 }),
                }
            },
            Some((_, Tok::Quoted(s))) => out.push(s),
            Some((line, t)) => {
                return Err(Error0::UnexpectedToken {
                    line,
                    token: format!("{t:?}"),
                })
            }
            None => {
                return Err(Error0::MissingArguments {
                    line: 0,
                    what: "string list".into(),
                })
            }
        }
        Ok(out)
    }

    fn parse_statements(&mut self, _requires: &mut Vec<String>) -> Result<Vec<Statement>, Error0> {
        let mut out = Vec::new();
        loop {
            let Some((line, tok)) = self.peek() else {
                break;
            };
            match tok {
                Tok::Word(w) => match w.as_str() {
                    "if" => {
                        self.advance();
                        let test = self.parse_test()?;
                        let then = self.parse_block()?;
                        // Peek without holding the borrow across advance.
                        let next_word = match self.peek() {
                            Some((_, Tok::Word(w))) => Some(w.clone()),
                            _ => None,
                        };
                        // elsif chains: each `elsif`/`else` is folded into
                        // the previous branch's `els` list so
                        // if A … elsif B … else C desugars to
                        // If{A, then, [If{B, thenB, [C-block]}]} (RFC 5228
                        // §3.1 — an elsif belongs to the enclosing if).
                        let els = match next_word.as_deref() {
                            Some("elsif") | Some("else") => self.parse_if_chain_tail()?,
                            _ => vec![],
                        };
                        out.push(Statement::If { test, then, els });
                    }
                    "fileinto" => {
                        self.advance();
                        let folder = self.expect_quoted("mailbox name")?;
                        self.expect_semicolon()?;
                        out.push(Statement::FileInto(folder));
                    }
                    "redirect" => {
                        self.advance();
                        let addr = self.expect_quoted("address")?;
                        self.expect_semicolon()?;
                        out.push(Statement::Redirect(addr));
                    }
                    "reject" => {
                        self.advance();
                        let reason = self.expect_quoted("reason")?;
                        self.expect_semicolon()?;
                        out.push(Statement::Reject(reason));
                    }
                    "vacation" => {
                        self.advance();
                        // Optional :days N
                        let mut days = 3;
                        if let Some((_, Tok::Tag(t))) = self.peek() {
                            if t == "days" {
                                self.advance();
                                if let Some((_, Tok::Number(n))) = self.advance() {
                                    days = n.min(30) as u32;
                                }
                            }
                        }
                        let reason = self.expect_quoted("vacation reason")?;
                        self.expect_semicolon()?;
                        out.push(Statement::Vacation { reason, days });
                    }
                    "keep" => {
                        self.advance();
                        self.expect_semicolon()?;
                        out.push(Statement::Keep);
                    }
                    "discard" => {
                        self.advance();
                        self.expect_semicolon()?;
                        out.push(Statement::Discard);
                    }
                    "stop" => {
                        self.advance();
                        self.expect_semicolon()?;
                        out.push(Statement::Stop);
                    }
                    other => {
                        return Err(Error0::UnexpectedToken {
                            line,
                            token: other.to_string(),
                        });
                    }
                },
                Tok::Semicolon => {
                    self.advance();
                }
                _ => break,
            }
        }
        Ok(out)
    }

    fn parse_block(&mut self) -> Result<Vec<Statement>, Error0> {
        match self.advance() {
            Some((_, Tok::BraceOpen)) => {}
            Some((line, t)) => {
                return Err(Error0::UnexpectedToken {
                    line,
                    token: format!("{t:?} (block)"),
                })
            }
            None => return Err(Error0::UnclosedBlock { line: 0 }),
        }
        let mut requires = Vec::new();
        let stmts = self.parse_statements(&mut requires)?;
        match self.advance() {
            Some((_, Tok::BraceClose)) => Ok(stmts),
            Some((line, _)) => Err(Error0::UnclosedBlock { line }),
            None => Err(Error0::UnclosedBlock { line: 0 }),
        }
    }

    fn expect_semicolon(&mut self) -> Result<(), Error0> {
        match self.advance() {
            Some((_, Tok::Semicolon)) => Ok(()),
            Some((line, t)) => Err(Error0::UnexpectedToken {
                line,
                token: format!("{t:?} (semicolon)"),
            }),
            None => Err(Error0::MissingArguments {
                line: 0,
                what: ";".into(),
            }),
        }
    }

    fn parse_test(&mut self) -> Result<Test, Error0> {
        let word = self.expect_word("test name")?;
        match word.as_str() {
            "true" => Ok(Test::True),
            "false" => Ok(Test::False),
            "not" => Ok(Test::Not(Box::new(self.parse_test()?))),
            "anyof" => Ok(Test::AnyOf(self.parse_test_list()?)),
            "allof" => Ok(Test::AllOf(self.parse_test_list()?)),
            "exists" => Ok(Test::Exists(self.parse_string_list()?)),
            "size" => {
                let mut over = None;
                let mut under = None;
                if let Some((_, Tok::Tag(t))) = self.peek() {
                    match t.as_str() {
                        "over" => {
                            self.advance();
                            if let Some((_, Tok::Number(n))) = self.advance() {
                                over = Some(n);
                            }
                        }
                        "under" => {
                            self.advance();
                            if let Some((_, Tok::Number(n))) = self.advance() {
                                under = Some(n);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Test::Size { over, under })
            }
            "header" => {
                let mut matcher = Matcher::Is;
                let mut comparator = Comparator::AsciiCaseMap;
                while let Some((_, Tok::Tag(t))) = self.peek() {
                    match t.as_str() {
                        "is" => matcher = Matcher::Is,
                        "contains" => matcher = Matcher::Contains,
                        "matches" => matcher = Matcher::Matches,
                        "comparator" => {
                            self.advance();
                            let c = self.expect_quoted("comparator")?;
                            if c == "i;ascii-numeric" {
                                comparator = Comparator::AsciiNumeric;
                            }
                        }
                        _ => {}
                    }
                    self.advance();
                }
                let names = self.parse_string_list()?;
                let keys = self.parse_string_list()?;
                Ok(Test::Header {
                    matcher,
                    comparator,
                    names,
                    keys,
                })
            }
            "address" => {
                let mut part = AddressPart::All;
                let mut matcher = Matcher::Is;
                while let Some((_, Tok::Tag(t))) = self.peek() {
                    match t.as_str() {
                        "localpart" => part = AddressPart::Local,
                        "domain" => part = AddressPart::Domain,
                        "is" => matcher = Matcher::Is,
                        "contains" => matcher = Matcher::Contains,
                        "matches" => matcher = Matcher::Matches,
                        _ => {}
                    }
                    self.advance();
                }
                let names = self.parse_string_list()?;
                let keys = self.parse_string_list()?;
                Ok(Test::Address {
                    part,
                    matcher,
                    names,
                    keys,
                })
            }
            "body" => {
                let mut matcher = Matcher::Contains;
                while let Some((_, Tok::Tag(t))) = self.peek() {
                    match t.as_str() {
                        "contains" => matcher = Matcher::Contains,
                        "is" => matcher = Matcher::Is,
                        "matches" => matcher = Matcher::Matches,
                        _ => {}
                    }
                    self.advance();
                }
                let keys = self.parse_string_list()?;
                Ok(Test::Body { matcher, keys })
            }
            "envelope" => {
                let mut part = EnvelopePart::From;
                let mut matcher = Matcher::Is;
                while let Some((_, Tok::Tag(t))) = self.peek() {
                    match t.as_str() {
                        "from" => part = EnvelopePart::From,
                        "to" => part = EnvelopePart::To,
                        "is" => matcher = Matcher::Is,
                        "contains" => matcher = Matcher::Contains,
                        "matches" => matcher = Matcher::Matches,
                        _ => {}
                    }
                    self.advance();
                }
                let keys = self.parse_string_list()?;
                Ok(Test::Envelope {
                    part,
                    matcher,
                    keys,
                })
            }
            other => Err(Error0::UnexpectedToken {
                line: 0,
                token: other.to_string(),
            }),
        }
    }

    fn parse_test_list(&mut self) -> Result<Vec<Test>, Error0> {
        let mut out = Vec::new();
        match self.advance() {
            Some((_, Tok::LParen)) => loop {
                out.push(self.parse_test()?);
                match self.advance() {
                    Some((_, Tok::Comma)) => continue,
                    Some((_, Tok::RParen)) => break,
                    Some((line, t)) => {
                        return Err(Error0::UnexpectedToken {
                            line,
                            token: format!("{t:?}"),
                        })
                    }
                    None => return Err(Error0::UnclosedBlock { line: 0 }),
                }
            },
            Some((line, t)) => {
                return Err(Error0::UnexpectedToken {
                    line,
                    token: format!("{t:?}"),
                })
            }
            None => {
                return Err(Error0::MissingArguments {
                    line: 0,
                    what: "test list".into(),
                })
            }
        }
        Ok(out)
    }

    /// Read the next statement list (block contents).
    #[allow(dead_code)]
    fn parse_top(&mut self) -> Result<Vec<Statement>, Error0> {
        let mut requires = Vec::new();
        self.parse_statements(&mut requires)
    }

    /// Parse the tail of an if/elsif/else chain (the caller has peeked
    /// `elsif` or `else`). Returns the else-branch statements: for an
    /// `elsif`, a single nested If whose own tail is parsed recursively;
    /// for `else`, the bare block. Nested blocks keep their own scope.
    fn parse_if_chain_tail(&mut self) -> Result<Vec<Statement>, Error0> {
        let next_word = match self.peek() {
            Some((_, Tok::Word(w))) => w.clone(),
            _ => return Ok(vec![]),
        };
        match next_word.as_str() {
            "elsif" => {
                self.advance();
                let test = self.parse_test()?;
                let then = self.parse_block()?;
                let els = self.parse_if_chain_tail()?;
                Ok(vec![Statement::If { test, then, els }])
            }
            "else" => {
                self.advance();
                self.parse_block()
            }
            _ => Ok(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tokenizer edges ───────────────────────────────────────────────

    #[test]
    fn comments_both_styles_ignored() {
        let s = compile("# line comment\nkeep; /* block\ncomment */ keep;");
        assert!(s.is_ok());
        assert_eq!(s.unwrap().statements.len(), 2);
    }

    #[test]
    fn unclosed_block_comment_is_error() {
        assert!(matches!(
            compile("keep; /* never closed"),
            Err(Error0::UnclosedBlock { .. })
        ));
    }

    #[test]
    fn unclosed_quoted_string_is_error() {
        assert!(matches!(
            compile("fileinto \"Box;"),
            Err(Error0::UnclosedBlock { .. })
        ));
    }

    #[test]
    fn quoted_string_escapes() {
        let s = compile(r#"fileinto "a\"b";"#).unwrap();
        assert_eq!(s.statements[0], Statement::FileInto("a\"b".into()));
    }

    #[test]
    fn unknown_character_is_unexpected_token() {
        // `@` is not part of the RFC 5228 token set we accept.
        assert!(matches!(
            compile("keep; @"),
            Err(Error0::UnexpectedToken { token, .. }) if token == "@"
        ));
    }

    #[test]
    fn numeric_literals() {
        let s = compile("if size :over 1024 { keep; }").unwrap();
        assert_eq!(
            s.statements[0],
            Statement::If {
                test: Test::Size {
                    over: Some(1024),
                    under: None
                },
                then: vec![Statement::Keep],
                els: vec![]
            }
        );
    }

    // ── Requires ──────────────────────────────────────────────────────

    #[test]
    fn known_requires_collected() {
        let s = compile(
            r#"require ["fileinto", "vacation", "comparator-i;ascii-numeric"];
vacation "gone";"#,
        )
        .unwrap();
        assert_eq!(s.requires.len(), 3);
    }

    #[test]
    fn every_known_require_accepted() {
        for r in KNOWN_REQUIRES {
            let src = format!("require [\"{r}\"];\nkeep;");
            assert!(compile(&src).is_ok(), "known require rejected: {r}");
        }
    }

    // ── Grammar ───────────────────────────────────────────────────────

    #[test]
    fn elsif_chain_parses() {
        let s = compile(
            r#"if header :is "subject" "a" { keep; }
elsif header :is "subject" "b" { discard; }
else { stop; }"#,
        )
        .unwrap();
        assert_eq!(s.statements.len(), 1);
        match &s.statements[0] {
            Statement::If { els, .. } => {
                // The elsif becomes a nested If in the else branch.
                assert!(matches!(els[0], Statement::If { .. }));
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn tagged_args_comparator_numeric() {
        let s =
            compile(r#"if header :comparator "i;ascii-numeric" :is "x-priority" "1" { keep; }"#)
                .unwrap();
        match &s.statements[0] {
            Statement::If {
                test:
                    Test::Header {
                        comparator,
                        matcher,
                        ..
                    },
                ..
            } => {
                assert_eq!(*comparator, Comparator::AsciiNumeric);
                assert_eq!(*matcher, Matcher::Is);
            }
            other => panic!("wrong test {other:?}"),
        }
    }

    #[test]
    fn address_parts_parse() {
        let s = compile(r#"if address :domain :is "from" "example.com" { keep; }"#).unwrap();
        match &s.statements[0] {
            Statement::If {
                test: Test::Address { part, .. },
                ..
            } => {
                assert_eq!(*part, AddressPart::Domain);
            }
            other => panic!("wrong test {other:?}"),
        }
    }

    #[test]
    fn missing_string_arg_is_error() {
        assert!(matches!(
            compile("fileinto;"),
            Err(Error0::UnexpectedToken { .. }) | Err(Error0::MissingArguments { .. })
        ));
    }

    #[test]
    fn unclosed_if_block_is_error() {
        assert!(matches!(
            compile("if true { keep;"),
            Err(Error0::UnclosedBlock { .. })
        ));
    }

    #[test]
    fn unknown_statement_word_is_error() {
        assert!(matches!(
            compile("frobnicate;"),
            Err(Error0::UnexpectedToken { token, .. }) if token == "frobnicate"
        ));
    }

    #[test]
    fn vacation_days_capped_at_30() {
        let s = compile(r#"vacation :days 999 "away";"#).unwrap();
        assert_eq!(
            s.statements[0],
            Statement::Vacation {
                reason: "away".into(),
                days: 30
            }
        );
    }

    #[test]
    fn envelope_test_parse() {
        let s = compile(
            r#"require ["envelope"];
if envelope :to :matches "*@example.net" { redirect "a@b.c"; }"#,
        )
        .unwrap();
        match &s.statements[0] {
            Statement::If {
                test:
                    Test::Envelope {
                        part,
                        matcher,
                        keys,
                    },
                ..
            } => {
                assert_eq!(*part, EnvelopePart::To);
                assert_eq!(*matcher, Matcher::Matches);
                assert_eq!(keys, &vec!["*@example.net".to_string()]);
            }
            other => panic!("wrong test {other:?}"),
        }
    }
}
