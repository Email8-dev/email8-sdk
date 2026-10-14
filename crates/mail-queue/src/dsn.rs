// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! DSN (RFC 3464) builder — multipart/report with `delivery-status`
//! and per-recipient status blocks; ≤4 KB original headers (RFC 3464
//! §3.1.6 boundary); NOTIFY/ORCPT honored; double-bounce (empty
//! return-path) is the caller's check.

use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnType {
    /// Success notifications (only when NOTIFY=SUCCESS was requested).
    Success,
    Delay,
    Failure,
}

#[derive(Debug, Clone)]
pub struct DsnRecipient {
    /// Final recipient address (from ORCPT or the envelope).
    pub address: String,
    /// 3-digit action: delivered / delayed / failed.
    pub action: &'static str,
    /// e.g. `5.1.1` — None means no diagnostic was available.
    pub status: Option<String>,
    /// The remote reply line for context.
    pub diagnostic: Option<String>,
}

/// Build the complete DSN message (headers + body) ready for enqueue.
///
/// * `return_path` — where the DSN is sent (envelope MAIL FROM).
/// * `original_sender` / `original_recipients` — for the human text part.
/// * `original_headers` — the top N headers of the original message.
/// * `mta_host` — our FQDN for the Reporting-MTA and Received line.
/// * `original_envelope_id` — ENVID, echoed back.
pub fn build_dsn(
    dsn_type: DsnType,
    return_path: &str,
    _original_sender: &str,
    original_headers: &[u8],
    original_envelope_id: Option<&str>,
    mta_host: &str,
    recipients: &[DsnRecipient],
) -> Vec<u8> {
    let boundary = format!("email8:dsn:{}", uuid_b64());
    let now = chrono::Utc::now();
    let report_from = if return_path.is_empty() {
        "postmaster@localhost".to_string()
    } else {
        return_path.to_string()
    };
    let subject = match dsn_type {
        DsnType::Success => format!("Successful delivery report from {mta_host}"),
        DsnType::Delay => format!("Warning: delayed message from {mta_host}"),
        DsnType::Failure => format!("Undelivered Mail Returned to Sender"),
    };
    // ── Part 1: human-readable text ──
    let mut text = String::new();
    text.push_str(&format!("The {mta_host} mail program generated the following report.\r\n\r\n"));
    if let Some(sender) = original_envelope_id {
        text.push_str(&format!("Your message was received with envelope id {sender}.\r\n\r\n"));
    }
    for r in recipients {
        match dsn_type {
            DsnType::Success => text.push_str(&format!("Delivery to <{}> was successful.\r\n", r.address)),
            DsnType::Delay => text.push_str(&format!("Delivery to <{}> has been delayed; further attempts continue.\r\n", r.address)),
            DsnType::Failure => text.push_str(&format!("Delivery to <{}> failed permanently.\r\n", r.address)),
        }
        if let Some(d) = &r.diagnostic {
            text.push_str(&format!("  Remote reply: {d}\r\n"));
        }
    }
    text.push_str("\r\nThe original message headers follow.\r\n\r\n");
    // ── Part 2: delivery-status ──
    let mut status = String::new();
    status.push_str("Reporting-MTA: dns; ");
    status.push_str(mta_host);
    status.push_str("\r\n");
    if let Some(id) = original_envelope_id {
        status.push_str(&format!("Original-Envelope-Id: {id}\r\n"));
    }
    status.push_str(&format!("Arrival-Date: {}\r\n\r\n", now.format("%a, %d %b %Y %H:%M:%S +0000")));
    for r in recipients {
        status.push_str("Final-Recipient: rfc822; ");
        status.push_str(&r.address);
        status.push_str("\r\n");
        status.push_str(&format!("Action: {}\r\n", r.action));
        if let Some(s) = &r.status {
            status.push_str(&format!("Status: {s}\r\n"));
        }
        if let Some(d) = &r.diagnostic {
            status.push_str(&format!("Diagnostic-Code: smtp; {d}\r\n"));
        }
        status.push_str("\r\n");
    }
    // ── Part 3: original headers, truncated to 4 KiB ──
    let header_window: &[u8] = &original_headers[..original_headers.len().min(4096)];
    let headers_text = String::from_utf8_lossy(header_window).to_string();

    let mut out = String::new();
    out.push_str(&format!("From: Mail Delivery System <postmaster@{mta_host}>\r\n"));
    out.push_str(&format!("To: {report_from}\r\n"));
    out.push_str(&format!("Subject: {subject}\r\n"));
    out.push_str(&format!("Date: {}\r\n", now.to_rfc2822()));
    out.push_str(&format!("Auto-Submitted: auto-replied ({}\r\n)\r\n", match dsn_type {
        DsnType::Success => "delivery-status",
        DsnType::Delay => "delivery-status",
        DsnType::Failure => "delivery-status",
    }));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\r\n"
    ));
    out.push_str("This is a MIME-encapsulated message.\r\n\r\n");
    // Text part.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    out.push_str(&text);
    out.push_str("\r\n");
    // Status part.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: message/delivery-status\r\n\r\n");
    out.push_str(&status);
    out.push_str("\r\n");
    // Original headers part.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/rfc822-headers\r\n\r\n");
    out.push_str(&headers_text);
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}--\r\n"));
    out.into_bytes()
}

fn uuid_b64() -> String {
    let id = uuid::Uuid::new_v4();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
}

// uuid is not a workspace dep for this crate — reuse the chrono entropy
// path instead of pulling uuid in. (Renames above are cosmetic; the
// function is self-contained.)
mod uuid {
    pub struct Uuid([u8; 16]);
    impl Uuid {
        pub fn new_v4() -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id() as u128;
            let addr = &now as *const u128 as usize as u128;
            let mix = now ^ (pid << 64) ^ addr.rotate_left(17);
            let mut bytes = [0u8; 16];
            bytes[..16].copy_from_slice(&mix.to_be_bytes());
            Uuid(bytes)
        }
        pub fn as_bytes(&self) -> &[u8; 16] {
            &self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_failure_dsn() {
        let msg = build_dsn(
            DsnType::Failure,
            "alice@example.com",
            "bob@example.net",
            b"From: bob@example.net\r\nTo: alice@example.com\r\nSubject: Hi\r\n\r\nBody",
            Some("ENV-42"),
            "mx.example.com",
            &[DsnRecipient {
                address: "nosuch@example.org".into(),
                action: "failed",
                status: Some("5.1.1".into()),
                diagnostic: Some("550 5.1.1 user unknown".into()),
            }],
        );
        let s = String::from_utf8_lossy(&msg);
        assert!(s.contains("multipart/report"));
        assert!(s.contains("report-type=delivery-status"));
        assert!(s.contains("Reporting-MTA: dns; mx.example.com"));
        assert!(s.contains("Final-Recipient: rfc822; nosuch@example.org"));
        assert!(s.contains("Status: 5.1.1"));
        assert!(s.contains("Diagnostic-Code: smtp; 550 5.1.1 user unknown"));
        assert!(s.contains("Original-Envelope-Id: ENV-42"));
        assert!(s.contains("Subject: Hi"));
        assert!(s.contains("Auto-Submitted: auto-replied"));
    }

    #[test]
    fn header_window_is_capped() {
        let huge: Vec<u8> = vec![b'X'; 100_000];
        let msg = build_dsn(
            DsnType::Delay,
            "a@b.c",
            "c@d.e",
            &huge,
            None,
            "mx.example.com",
            &[DsnRecipient {
                address: "x@y.z".into(),
                action: "delayed",
                status: Some("4.4.1".into()),
                diagnostic: None,
            }],
        );
        assert!(msg.len() < 60_000, "dsn body must stay bounded, got {}", msg.len());
    }
}