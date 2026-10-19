// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Incremental SMTP line receiver.
//!
//! Bytes are fed from the socket; the receiver buffers until a CRLF
//! terminates a command line. Pipelining is inherent - several complete
//! lines may be drained from one socket read. BDAT chunk bodies are
//! consumed verbatim (byte-counted, not line-scanned).

use crate::command::Command;

/// Receiver state - buffering partial lines/chunks between socket reads.
#[derive(Debug, Default)]
pub struct Receiver {
    buffer: Vec<u8>,
    /// Pending BDAT chunk: (remaining size, last) - set when a BDAT
    /// command line arrives before its body bytes did.
    pending_chunk: Option<(usize, bool)>,
    /// Plain-DATA mode (RFC 5321 §4.1.1.4): active between `DATA` and
    /// the lone `.` terminator line. All lines accumulate (with
    /// dot-unstuffing) into a DataChunk; the terminator is stripped.
    data_mode: bool,
}

/// A complete element pulled from the byte stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Element {
    /// A parsed command line (without CRLF).
    Command(Command),
    /// A raw line that failed to parse (caller replies `500`).
    Invalid(String),
    /// BDAT payload of exactly `size` bytes (consumed verbatim).
    DataChunk { data: Vec<u8>, last: bool },
}

impl Receiver {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1024),
            pending_chunk: None,
            data_mode: false,
        }
    }

    /// Enter plain-DATA mode - called by the session right after it
    /// replies `354` to `DATA`. Subsequent lines are message content
    /// until the lone `.` terminator.
    pub fn begin_data(&mut self) {
        self.data_mode = true;
    }

    /// Feed raw socket bytes; returns completed elements. BDAT bodies
    /// are consumed byte-counted; the `last` flag from the BDAT command
    /// line is carried onto the emitted chunk.
    pub fn parse(&mut self, bytes: &[u8]) -> Vec<Element> {
        let mut out = Vec::new();
        self.buffer.extend_from_slice(bytes);
        loop {
            // A pending BDAT body is consumed verbatim, byte-counted.
            if let Some((size, last)) = self.pending_chunk {
                if self.buffer.len() < size {
                    break; // wait for the full chunk
                }
                let data: Vec<u8> = self.buffer.drain(..size).collect();
                self.pending_chunk = None;
                out.push(Element::DataChunk { data, last });
                continue;
            }
            // Plain-DATA mode: accumulate lines (dot-unstuffed) until the
            // lone `.` terminator, which is stripped (RFC 5321 §4.5.2).
            if self.data_mode {
                let mut body: Vec<u8> = Vec::new();
                let mut terminated = false;
                loop {
                    match self.buffer.iter().position(|&b| b == b'\n') {
                        Some(pos) => {
                            let mut line: Vec<u8> = self.buffer.drain(..=pos).collect();
                            line.pop(); // strip \n
                            if line.last() == Some(&b'\r') {
                                line.pop(); // strip \r
                            }
                            if line == b"." {
                                // Terminator - do not include it.
                                self.data_mode = false;
                                terminated = true;
                                break;
                            }
                            // Dot-unstuffing: a leading "." before content
                            // is stripped (RFC 5321 §4.5.2).
                            if line.first() == Some(&b'.') {
                                line.remove(0);
                            }
                            line.extend_from_slice(b"\r\n");
                            body.extend_from_slice(&line);
                        }
                        None => break,
                    }
                }
                if !body.is_empty() {
                    out.push(Element::DataChunk {
                        data: body,
                        last: terminated,
                    });
                } else if terminated {
                    out.push(Element::DataChunk {
                        data: Vec::new(),
                        last: true,
                    });
                }
                if terminated {
                    continue;
                }
                break; // wait for more data bytes
            }
            match self.buffer.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    let line: Vec<u8> = self.buffer.drain(..=pos).collect();
                    let line = String::from_utf8_lossy(&line[..line.len() - 1])
                        .trim_end_matches('\r')
                        .to_string();
                    match Command::parse(&line) {
                        Some(Command::Bdat { size, last }) => {
                            out.push(Element::Command(Command::Bdat { size, last }));
                            // The BDAT body is NOT CRLF-terminated (RFC 3030
                            // - byte-counted). Remember it and consume verbatim
                            // on this or the next parse() pass.
                            if self.buffer.len() >= size {
                                let data: Vec<u8> = self.buffer.drain(..size).collect();
                                out.push(Element::DataChunk { data, last });
                            } else {
                                self.pending_chunk = Some((size, last));
                                break;
                            }
                        }
                        Some(other) => out.push(Element::Command(other)),
                        None => out.push(Element::Invalid(line)),
                    }
                }
                None => break,
            }
        }
        out
    }

    /// Drain a pending BDAT chunk once its bytes arrive (used by the
    /// session after a `parse` that left a partial chunk in the buffer).
    pub fn take_chunk(&mut self, size: usize) -> Option<Vec<u8>> {
        if self.buffer.len() < size {
            return None;
        }
        Some(self.buffer.drain(..size).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drains_pipelined_commands() {
        let mut r = Receiver::new();
        let els = r.parse(b"EHLO a.com\r\nMAIL FROM:<x@y.z>\r\n");
        assert_eq!(els.len(), 2);
        assert!(matches!(els[0], Element::Command(Command::Ehlo { .. })));
        assert!(matches!(els[1], Element::Command(Command::MailFrom { .. })));
    }

    #[test]
    fn buffers_partial_lines() {
        let mut r = Receiver::new();
        let els = r.parse(b"MAIL FR");
        assert!(els.is_empty());
        let els = r.parse(b"OM:<a@b.c>\r\n");
        assert_eq!(els.len(), 1);
    }

    #[test]
    fn consumes_bdat_chunk_verbatim() {
        let mut r = Receiver::new();
        let els = r.parse(b"BDAT 5 LAST\r\nhello");
        assert_eq!(els.len(), 2);
        assert!(matches!(
            els[0],
            Element::Command(Command::Bdat {
                size: 5,
                last: true
            })
        ));
        assert!(matches!(&els[1], Element::DataChunk { data, last: true } if data == b"hello"));
    }

    #[test]
    fn buffers_partial_bdat_chunk() {
        let mut r = Receiver::new();
        let els = r.parse(b"BDAT 10\r\nabc");
        assert_eq!(els.len(), 1);
        assert!(matches!(
            els[0],
            Element::Command(Command::Bdat {
                size: 10,
                last: false
            })
        ));
        // Feed the remaining 7 chunk bytes plus a trailing command line:
        // the 10-byte chunk drains, then "NOOP" parses normally.
        let els = r.parse(b"defghijNOOP\r\nklm");
        assert_eq!(els.len(), 2);
        assert!(
            matches!(&els[0], Element::DataChunk { data, last: false } if data == b"abcdefghij")
        );
        assert!(matches!(els[1], Element::Command(Command::Noop)));
        // "klm" (no CRLF yet) stays buffered - completing it yields Invalid.
        let els = r.parse(b"\r\n");
        assert_eq!(els.len(), 1);
        assert!(matches!(els[0], Element::Invalid(_)));
    }
}
