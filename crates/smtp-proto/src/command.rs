// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Typed SMTP command model (server role).

use std::net::IpAddr;

/// A parsed inbound SMTP command. Envelope transaction state stays in the
/// session; this is purely the wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `HELO domain`
    Helo { host: String },
    /// `EHLO domain`
    Ehlo { host: String },
    /// `LHLO domain` (LMTP)
    Lhlo { host: String },
    /// `STARTTLS`
    StartTls,
    /// `AUTH mechanism [initial-response]`
    Auth {
        mechanism: String,
        initial: Option<String>,
    },
    /// SASL continuation line (raw base64, possibly `*` cancel).
    Sasl { token: String },
    /// `MAIL FROM:<addr> [params]`
    MailFrom {
        address: Option<String>,
        params: Vec<(String, Option<String>)>,
    },
    /// `RCPT TO:<addr> [params]`
    RcptTo {
        address: String,
        params: Vec<(String, Option<String>)>,
    },
    /// `DATA`
    Data,
    /// `BDAT n [LAST]` (CHUNKING)
    Bdat { size: usize, last: bool },
    /// `RSET`
    Reset,
    /// `NOOP [text]`
    Noop,
    /// `QUIT`
    Quit,
    /// `VRFY address`
    Vrfy { address: String },
    /// `EXPN address`
    Expn { address: String },
    /// `HELP`
    Help,
}

/// A parsed `MAIL FROM`/`RCPT TO` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpParam {
    pub keyword: String,
    pub value: Option<String>,
}

impl Command {
    /// Parse one complete command line (no trailing CRLF). Returns `None`
    /// for unparseable input (caller answers `500 5.5.2`).
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return Some(Self::Noop);
        }
        let (verb, rest) = match line.find(' ') {
            Some(pos) => (&line[..pos], line[pos + 1..].trim_start()),
            None => (line, ""),
        };
        match verb.to_ascii_uppercase().as_str() {
            "HELO" => Some(Self::Helo {
                host: rest.to_string(),
            }),
            "EHLO" => Some(Self::Ehlo {
                host: rest.to_string(),
            }),
            "LHLO" => Some(Self::Lhlo {
                host: rest.to_string(),
            }),
            "STARTTLS" => Some(Self::StartTls),
            "AUTH" => {
                let mut parts = rest.splitn(2, ' ');
                let mechanism = parts.next()?.to_ascii_uppercase();
                if mechanism.is_empty() {
                    return None;
                }
                let initial = parts.next().map(|s| s.to_string());
                Some(Self::Auth { mechanism, initial })
            }
            "MAIL" => {
                // MAIL FROM:<addr> PARAM=VALUE ...
                let (addr, params) = parse_path_and_params(rest, "FROM:")?;
                Some(Self::MailFrom {
                    address: addr,
                    params,
                })
            }
            "RCPT" => {
                let (addr, params) = parse_path_and_params(rest, "TO:")?;
                Some(Self::RcptTo {
                    address: addr?,
                    params,
                })
            }
            "DATA" => Some(Self::Data),
            "BDAT" => {
                let mut parts = rest.split_whitespace();
                let size = parts.next()?.parse().ok()?;
                let last = parts
                    .next()
                    .map(|p| p.eq_ignore_ascii_case("LAST"))
                    .unwrap_or(false);
                Some(Self::Bdat { size, last })
            }
            "RSET" => Some(Self::Reset),
            "NOOP" => Some(Self::Noop),
            "QUIT" => Some(Self::Quit),
            "VRFY" => Some(Self::Vrfy {
                address: rest.to_string(),
            }),
            "EXPN" => Some(Self::Expn {
                address: rest.to_string(),
            }),
            "HELP" => Some(Self::Help),
            _ => None,
        }
    }
}

/// Parse `FROM:<addr>` / `TO:<addr>` plus trailing `KEY=VALUE` parameters.
/// `FROM:<>` (null sender) yields `Ok(None)`.
fn parse_path_and_params(
    rest: &str,
    prefix: &str,
) -> Option<(Option<String>, Vec<(String, Option<String>)>)> {
    if !rest.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = &rest[prefix.len()..];
    let (path, tail) = match rest.find('>') {
        Some(end) => (&rest[..end], rest[end + 1..].trim_start()),
        None => (rest.trim(), ""),
    };
    let path = path.trim().trim_start_matches('<');
    let address = if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    };
    let params = tail
        .split_whitespace()
        .filter(|p| !p.is_empty())
        .map(|p| match p.find('=') {
            Some(eq) => (p[..eq].to_ascii_uppercase(), Some(p[eq + 1..].to_string())),
            None => (p.to_ascii_uppercase(), None),
        })
        .collect();
    Some((address, params))
}

/// Parameter helpers - the session consumes these directly.
impl Command {
    pub fn param(&self, keyword: &str) -> Option<&Option<String>> {
        let params = match self {
            Self::MailFrom { params, .. } | Self::RcptTo { params, .. } => params,
            _ => return None,
        };
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(keyword))
            .map(|(_, v)| v)
    }
}

/// Normalize an IP-literal HELO/EHLO argument (e.g. `[127.0.0.1]`).
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let inner = host.trim_start_matches('[').trim_end_matches(']');
    inner.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ehlo_and_mail() {
        let c = Command::parse("EHLO mail.example.com").unwrap();
        assert_eq!(
            c,
            Command::Ehlo {
                host: "mail.example.com".into()
            }
        );
        let c = Command::parse("MAIL FROM:<alice@example.com> SIZE=1234 BODY=8BITMIME").unwrap();
        match c {
            Command::MailFrom { address, params } => {
                assert_eq!(address.as_deref(), Some("alice@example.com"));
                assert_eq!(params.len(), 2);
                assert_eq!(params[0].0, "SIZE");
                assert_eq!(params[0].1.as_deref(), Some("1234"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_null_sender() {
        let c = Command::parse("MAIL FROM:<>").unwrap();
        assert!(matches!(c, Command::MailFrom { address: None, .. }));
    }

    #[test]
    fn parses_rcpt_with_orcpt() {
        let c = Command::parse(
            "RCPT TO:<bob@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;bob@example.com",
        )
        .unwrap();
        match c {
            Command::RcptTo { address, params } => {
                assert_eq!(address, "bob@example.com");
                assert_eq!(params.len(), 2);
                assert_eq!(params[1].0, "ORCPT");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(Command::parse("FOO BAR").is_none());
    }
}
