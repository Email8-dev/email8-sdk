// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! PROXY protocol v2 - upstream-side header parsing (gate design §3.3,
//! story 7.4).
//!
//! The gate prepends a v2 header carrying the real client address.
//! Upstream raw listeners parse (and consume) it when the
//! `EMAIL8_{MTA,ACCESS}_ACCEPT_PROXY` env is set for the listener -
//! keeping direct-bind dev traffic untouched.
//!
//! Byte layout (HAProxy spec §2.2): 12-byte signature, version|command
//! byte, family|transport byte, big-endian address length, then the
//! address block (IPv4: 4 src + 4 dst + 2+2 ports = 12 B; IPv6: 36 B).

/// v2 binary signature.
const SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Fixed prefix: 12 signature + version|command + family|transport +
/// 2-byte length = 16 bytes before the address block.
const FIXED_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Addresses {
    /// The real client address (the gate's peer).
    pub source: std::net::SocketAddr,
    /// The address the client connected to (the gate listener).
    pub destination: std::net::SocketAddr,
}

/// Parse error - a malformed header is unrecoverable (the stream is
/// desynchronized); callers must close the connection.
#[derive(Debug, thiserror::Error)]
pub enum ProxyV2Error {
    #[error("truncated PROXY v2 header (need {needed}, got {got})")]
    Truncated { needed: usize, got: usize },
    #[error("bad PROXY v2 signature")]
    BadSignature,
    #[error("unsupported PROXY version/command byte 0x{0:02x}")]
    BadVersionCommand(u8),
    #[error("unsupported PROXY family byte 0x{0:02x}")]
    BadFamily(u8),
    #[error("PROXY v2 address length {0} out of range")]
    BadLength(usize),
}

/// Parse a complete PROXY v2 header from the front of `buf`.
/// Returns the parsed addresses and the total header length to consume.
pub fn parse_v2_header(buf: &[u8]) -> Result<(V2Addresses, usize), ProxyV2Error> {
    if buf.len() < FIXED_LEN {
        return Err(ProxyV2Error::Truncated {
            needed: FIXED_LEN,
            got: buf.len(),
        });
    }
    if buf[..12] != SIG {
        return Err(ProxyV2Error::BadSignature);
    }
    // version|command: high nibble must be 2 (v2); command LOCAL(0)/PROXY(1).
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return Err(ProxyV2Error::BadVersionCommand(ver_cmd));
    }
    let family = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = FIXED_LEN + addr_len;
    if buf.len() < total {
        return Err(ProxyV2Error::Truncated {
            needed: total,
            got: buf.len(),
        });
    }
    let addr = &buf[FIXED_LEN..total];
    match family {
        // INET (IPv4), STREAM
        0x21 => {
            if addr_len < 12 {
                return Err(ProxyV2Error::BadLength(addr_len));
            }
            let src = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                u16::from_be_bytes([addr[8], addr[9]]),
            );
            let dst = std::net::SocketAddr::new(
                std::net::Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]).into(),
                u16::from_be_bytes([addr[10], addr[11]]),
            );
            Ok((
                V2Addresses {
                    source: src,
                    destination: dst,
                },
                total,
            ))
        }
        // INET6, STREAM
        0x22 => {
            if addr_len < 36 {
                return Err(ProxyV2Error::BadLength(addr_len));
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&addr[..16]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&addr[16..32]);
            let src_port = u16::from_be_bytes([addr[32], addr[33]]);
            let dst_port = u16::from_be_bytes([addr[34], addr[35]]);
            Ok((
                V2Addresses {
                    source: (src, src_port).into(),
                    destination: (dst, dst_port).into(),
                },
                total,
            ))
        }
        _ => Err(ProxyV2Error::BadFamily(family)),
    }
}

/// Whether this listener should parse a leading PROXY header.
pub fn accept_proxy_from_env(service_env: &str) -> bool {
    std::env::var(service_env)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Test-side header builders mirroring the gate's `proxy_v2` constructor
/// (kept here so the contract tests stay self-contained).
#[cfg(test)]
pub(crate) mod gate_v2 {
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    pub fn v2_tcp4(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&SIG);
        b.push(0x21);
        b.push(0x21);
        b.extend_from_slice(&12u16.to_be_bytes());
        b.extend_from_slice(&src_ip);
        b.extend_from_slice(&dst_ip);
        b.extend_from_slice(&src_port.to_be_bytes());
        b.extend_from_slice(&dst_port.to_be_bytes());
        b
    }
    pub fn v2_tcp6(src_ip: [u8; 16], src_port: u16, dst_ip: [u8; 16], dst_port: u16) -> Vec<u8> {
        let mut b = Vec::with_capacity(52);
        b.extend_from_slice(&SIG);
        b.push(0x21);
        b.push(0x22);
        b.extend_from_slice(&36u16.to_be_bytes());
        b.extend_from_slice(&src_ip);
        b.extend_from_slice(&dst_ip);
        b.extend_from_slice(&src_port.to_be_bytes());
        b.extend_from_slice(&dst_port.to_be_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp4_header() {
        // Build with the gate's constructor for symmetry.
        let header = super::gate_v2::v2_tcp4([192, 0, 2, 1], 45678, [203, 0, 113, 9], 25);
        let (addrs, len) = parse_v2_header(&header).unwrap();
        assert_eq!(len, 28);
        assert_eq!(addrs.source.to_string(), "192.0.2.1:45678");
        assert_eq!(addrs.destination.to_string(), "203.0.113.9:25");
    }

    #[test]
    fn parses_tcp6_header() {
        let header = super::gate_v2::v2_tcp6([1u8; 16], 1111, [2u8; 16], 2222);
        let (addrs, len) = parse_v2_header(&header).unwrap();
        assert_eq!(len, 52);
        assert_eq!(addrs.source.port(), 1111);
        assert_eq!(addrs.destination.port(), 2222);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut header = super::gate_v2::v2_tcp4([1, 1, 1, 1], 1, [2, 2, 2, 2], 2);
        header[3] = 0xFF;
        assert!(matches!(
            parse_v2_header(&header),
            Err(ProxyV2Error::BadSignature)
        ));
    }

    #[test]
    fn rejects_truncated_header() {
        let header = super::gate_v2::v2_tcp4([1, 1, 1, 1], 1, [2, 2, 2, 2], 2);
        let (addrs, len) = parse_v2_header(&header).unwrap();
        assert_eq!(addrs.source.port(), 1);
        let _ = len;
        let short = &header[..20];
        assert!(matches!(
            parse_v2_header(short),
            Err(ProxyV2Error::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_non_proxy_version() {
        let mut header = super::gate_v2::v2_tcp4([1, 1, 1, 1], 1, [2, 2, 2, 2], 2);
        header[12] = 0x11; // version 1
        assert!(matches!(
            parse_v2_header(&header),
            Err(ProxyV2Error::BadVersionCommand(0x11))
        ));
    }

    #[test]
    fn env_flag_parsing() {
        std::env::set_var("EMAIL8_TEST_ACCEPT_PROXY", "true");
        assert!(accept_proxy_from_env("EMAIL8_TEST_ACCEPT_PROXY"));
        std::env::set_var("EMAIL8_TEST_ACCEPT_PROXY", "false");
        assert!(!accept_proxy_from_env("EMAIL8_TEST_ACCEPT_PROXY"));
        std::env::remove_var("EMAIL8_TEST_ACCEPT_PROXY");
        assert!(!accept_proxy_from_env("EMAIL8_TEST_ACCEPT_PROXY"));
    }
}
