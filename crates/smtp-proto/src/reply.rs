// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! SMTP reply construction - status codes, enhanced status codes, and the
//! canonical replies used by the inbound pipeline (parity with the legacy
//! response strings).

/// A complete SMTP reply (code, enhanced status, text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub enhanced: Option<(u8, u8, u8)>,
    pub text: String,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: None,
            text: text.into(),
        }
    }

    pub fn enhanced(code: u16, major: u8, minor: u8, detail: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: Some((major, minor, detail as u8)),
            text: text.into(),
        }
    }

    /// Serialize to wire form (single-line).
    pub fn to_wire(&self) -> String {
        match self.enhanced {
            Some((a, b, c)) => format!("{} {}.{}.{} {}\r\n", self.code, a, b, c, self.text),
            None => format!("{} {}\r\n", self.code, self.text),
        }
    }
}

/// Canonical replies used by the Mta inbound pipeline.
pub fn greeting(hostname: &str) -> Reply {
    Reply::new(220, format!("{hostname} Email8 Mta at your service."))
}

pub fn ehlo(hostname: &str, capabilities: &[String]) -> Vec<String> {
    let mut lines = vec![format!("250-{hostname} at your service.")];
    if capabilities.is_empty() {
        lines.push("250 OK".to_string());
        return lines;
    }
    for (i, cap) in capabilities.iter().enumerate() {
        if i + 1 == capabilities.len() {
            lines.push(format!("250 {cap}"));
        } else {
            lines.push(format!("250-{cap}"));
        }
    }
    lines
}

pub fn ok() -> Reply {
    Reply::new(250, "OK")
}

pub fn ok_queued(queue_id: &str) -> Reply {
    Reply::new(
        250,
        format!("Message accepted for delivery (queue {queue_id})"),
    )
}

pub fn starttls_ready() -> Reply {
    Reply::new(220, "Ready to start TLS")
}

pub fn auth_continue(challenge: &str) -> Reply {
    Reply::new(334, challenge)
}

pub fn auth_success() -> Reply {
    Reply::new(235, "Authentication successful")
}

pub fn auth_failed() -> Reply {
    Reply::enhanced(535, 5, 7, 8, "Authentication failed")
}

pub fn auth_too_many_errors() -> Reply {
    Reply::enhanced(455, 4, 3, 0, "Too many authentication errors")
}

pub fn auth_required() -> Reply {
    Reply::enhanced(530, 5, 7, 1, "Authentication required")
}

pub fn need_ehlo() -> Reply {
    Reply::enhanced(503, 5, 5, 1, "Polite people say EHLO first")
}

pub fn need_mail_first() -> Reply {
    Reply::new(503, "Need MAIL command before RCPT")
}

pub fn need_rcpt_first() -> Reply {
    Reply::new(503, "Need RCPT command before DATA")
}

pub fn unknown_command() -> Reply {
    Reply::new(500, "Command not recognized")
}

pub fn bad_syntax() -> Reply {
    Reply::enhanced(501, 5, 5, 4, "Invalid command syntax")
}

pub fn sender_not_allowed() -> Reply {
    Reply::enhanced(550, 5, 7, 1, "Sender address not allowed")
}

pub fn sender_binding_rejected() -> Reply {
    Reply::enhanced(
        501,
        5,
        5,
        4,
        "You are not allowed to send from this address",
    )
}

pub fn rcpt_not_found() -> Reply {
    Reply::enhanced(550, 5, 1, 2, "Mailbox does not exist")
}

pub fn relay_denied() -> Reply {
    Reply::enhanced(550, 5, 1, 2, "Relay not allowed")
}

pub fn too_many_recipients() -> Reply {
    Reply::enhanced(455, 4, 5, 3, "Too many recipients")
}

pub fn message_too_large(max: u64) -> Reply {
    Reply::enhanced(552, 5, 3, 4, format!("Message too large (max {max} bytes)"))
}

pub fn loop_detected() -> Reply {
    Reply::enhanced(450, 4, 4, 6, "Mail forwarding loop detected")
}

pub fn dmarc_reject() -> Reply {
    Reply::enhanced(550, 5, 7, 1, "Email rejected per DMARC policy")
}

pub fn spam_reject() -> Reply {
    Reply::enhanced(550, 5, 7, 1, "Message rejected due to excessive spam score")
}

pub fn greylisted() -> Reply {
    Reply::enhanced(
        452,
        4,
        2,
        2,
        "Greylisted, please try again in a few moments",
    )
}

pub fn rate_limited() -> Reply {
    Reply::enhanced(452, 4, 4, 5, "Rate limit exceeded")
}

pub fn queue_full() -> Reply {
    Reply::enhanced(452, 4, 3, 1, "Mail system full")
}

pub fn transfer_quota() -> Reply {
    Reply::enhanced(452, 4, 7, 28, "Transfer quota exceeded")
}

pub fn parse_failed() -> Reply {
    Reply::enhanced(550, 5, 7, 7, "Message could not be parsed")
}

pub fn auth_mechanism_unknown() -> Reply {
    Reply::new(504, "Mechanism not supported")
}

pub fn closing(hostname: &str) -> Reply {
    Reply::new(221, format!("{hostname} closing connection"))
}

pub fn reverse_dns_failed() -> Reply {
    Reply::enhanced(550, 5, 7, 25, "Reverse DNS validation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_serialization() {
        assert_eq!(Reply::new(250, "OK").to_wire(), "250 OK\r\n");
        let r = Reply::enhanced(550, 5, 1, 2, "Mailbox does not exist");
        assert_eq!(r.to_wire(), "550 5.1.2 Mailbox does not exist\r\n");
    }

    #[test]
    fn ehlo_capability_lines() {
        let lines = ehlo(
            "mx.example.com",
            &["SIZE 26214400".into(), "PIPELINING".into()],
        );
        assert_eq!(lines[0], "250-mx.example.com at your service.");
        assert_eq!(lines[1], "250-SIZE 26214400");
        assert_eq!(lines[2], "250 PIPELINING");
    }
}
