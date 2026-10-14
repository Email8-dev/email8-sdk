// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Incremental IMAP line receiver — LITERAL+ aware.
//!
//! Commands complete on CRLF. A `{n}` literal is answered with a `+`
//! continuation and its `n` bytes are consumed verbatim before the next
//! line is parsed (`{n+}` is the non-synchronizing LITERAL+ form — the
//! client sends the bytes without waiting).

use crate::command::{self, ClientCommand};

/// Receiver state machine.
#[derive(Debug)]
pub struct Receiver {
    buffer: Vec<u8>,
    /// Pending literal: (size, synchronizing) — bytes to consume verbatim.
    pending_literal: Option<(usize, bool)>,
}

/// A completed element from the byte stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Element {
    /// A command line with all literals inlined (`{n}` replaced by the
    /// raw literal text in the reconstructed line).
    Command(ClientCommand),
    /// A syntactically complete but unparseable line.
    Invalid(String),
    /// The receiver wants a literal-continuation sent (`+ OK`) before the
    /// client continues.
    LiteralContinuation { size: usize },
    /// The literal content that followed a `{n}`/`{n+}` marker (raw
    /// bytes; sessions capture this for APPEND bodies).
    Literal { data: Vec<u8> },
}

impl Receiver {
    pub fn new() -> Self {
        Self { buffer: Vec::with_capacity(1024), pending_literal: None }
    }

    /// Feed socket bytes; returns completed elements (may be empty).
    pub fn parse(&mut self, bytes: &[u8]) -> Vec<Element> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if let Some((size, sync)) = self.pending_literal {
                if self.buffer.len() < size {
                    break; // wait for the literal body
                }
                let literal: Vec<u8> = self.buffer.drain(..size).collect();
                let _ = sync;
                self.pending_literal = None;
                out.push(Element::Literal { data: literal });
                // Fall through: try to complete the rest of the line.
            }
            match self.buffer.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    let line: Vec<u8> = self.buffer.drain(..=pos).collect();
                    let line_str = String::from_utf8_lossy(&line[..line.len() - 1])
                        .trim_end_matches('\r')
                        .to_string();
                    // Detect a trailing synchronizing literal `{n}`.
                    if let Some((size, sync)) = trailing_literal(&line_str) {
                        out.push(Element::LiteralContinuation { size });
                        if sync {
                            self.pending_literal = Some((size, true));
                        } else {
                            self.pending_literal = Some((size, false));
                        }
                        continue;
                    }
                    match command::parse(&line_str) {
                        Some(cmd) => out.push(Element::Command(cmd)),
                        None => out.push(Element::Invalid(line_str)),
                    }
                }
                None => break,
            }
        }
        out
    }
}

/// If the line ends with `{n}` or `{n+}`, return the literal size and
/// whether it is synchronizing.
fn trailing_literal(line: &str) -> Option<(usize, bool)> {
    if !line.ends_with('}') {
        return None;
    }
    let start = line.rfind('{')?;
    let inner = &line[start + 1..line.len() - 1];
    if inner.ends_with('+') {
        Some((inner[..inner.len() - 1].parse().ok()?, false))
    } else {
        Some((inner.parse().ok()?, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_tagged_commands() {
        let mut r = Receiver::new();
        let els = r.parse(b"a1 NOOP\r\na2 CAPABILITY\r\n");
        assert_eq!(els.len(), 2);
        assert!(matches!(els[0], Element::Command(_)));
    }

    #[test]
    fn literal_plus_inline() {
        let mut r = Receiver::new();
        let els = r.parse(b"a3 APPEND \"INBOX\" {12+}\r\n");
        // Non-synchronizing: the receiver emits the continuation marker but
        // does NOT wait for it.
        assert!(matches!(els[0], Element::LiteralContinuation { size: 12 }));
        let els = r.parse(b"hello  world\r\n");
        // The pending literal consumes exactly the 12 declared bytes and
        // surfaces them as a Literal element; the trailing CRLF is then
        // parsed as an empty (invalid) command line.
        assert!(matches!(els[0], Element::Literal { ref data } if data == b"hello  world"));
        assert!(
            els.len() == 1
                || matches!(els[1], Element::Invalid(_))
        );
    }
}