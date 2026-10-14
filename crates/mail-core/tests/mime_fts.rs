// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! MIME tree + FTS tests (stories 2.1/2.6).

use email8_mail_core::{calendar_bodies, detect_tsvector_lang, first_text_body, snippet, walk_parts};

const MULTIPART: &[u8] = b"From: alice@example.com\r\n\
To: bob@example.net\r\n\
Subject: hi\r\n\
Content-Type: multipart/alternative; boundary=\"XYZ\"\r\n\
\r\n\
preamble\r\n\
--XYZ\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello plain world\r\n\
--XYZ\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
<p>Hello =41=42=43 html</p>\r\n\
--XYZ--\r\n";

const ATTACHMENT: &[u8] = b"From: a@b.c\r\n\
Subject: doc\r\n\
Content-Type: multipart/mixed; boundary=\"BB\"\r\n\
\r\n\
--BB\r\n\
Content-Type: text/plain\r\n\
\r\n\
see attached\r\n\
--BB\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQ=\r\n\
--BB--\r\n";

#[test]
fn multipart_tree_walk() {
    let parts = walk_parts(MULTIPART);
    // Root container + 2 leaves.
    assert_eq!(parts.len(), 3);
    assert!(parts[0].is_multipart());
    assert_eq!(parts[0].content_type, "multipart/alternative");
    assert_eq!(parts[1].content_type, "text/plain");
    assert_eq!(parts[1].charset, "utf-8");
    assert_eq!(parts[2].content_type, "text/html");
    assert_eq!(parts[2].transfer_encoding, "quoted-printable");
}

#[test]
fn first_text_body_decodes() {
    let parts = walk_parts(MULTIPART);
    let text = first_text_body(MULTIPART, &parts).expect("text/plain present");
    assert_eq!(String::from_utf8_lossy(&text).trim_end(), "Hello plain world");
    // QP decode on the html part.
    let html = &parts[2];
    assert_eq!(html.transfer_encoding, "quoted-printable");
    let body = email8_mail_core::decode_part(MULTIPART, html);
    assert!(String::from_utf8_lossy(&body).contains("Hello ABC html"));
}

#[test]
fn attachment_detection_and_base64() {
    let parts = walk_parts(ATTACHMENT);
    let pdf = parts.iter().find(|p| p.content_type == "application/pdf").expect("pdf part");
    assert!(pdf.is_attachment());
    assert_eq!(pdf.filename.as_deref(), Some("report.pdf"));
    let body = email8_mail_core::decode_part(ATTACHMENT, pdf);
    assert_eq!(String::from_utf8_lossy(&body), "%PDF-1.4");
    // The plain part is not an attachment.
    let plain = parts.iter().find(|p| p.content_type == "text/plain").unwrap();
    assert!(!plain.is_attachment());
}

#[test]
fn calendar_part_extraction() {
    let raw = b"From: x@y.z\r\nContent-Type: multipart/mixed; boundary=\"C\"\r\n\r\n\
--C\r\nContent-Type: text/plain\r\n\r\nmeeting\r\n\
--C\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\nUID:123\r\nEND:VCALENDAR\r\n\
--C--\r\n";
    let parts = walk_parts(raw);
    let cals = calendar_bodies(raw, &parts);
    assert_eq!(cals.len(), 1);
    assert!(String::from_utf8_lossy(&cals[0]).contains("BEGIN:VCALENDAR"));
}

#[test]
fn malformed_fallback() {
    // No boundary terminator — final segment takes the rest.
    let raw = b"From: a@b.c\r\nContent-Type: multipart/mixed; boundary=\"Z\"\r\n\r\n--Z\r\nContent-Type: text/plain\r\n\r\nunterminated body";
    let parts = walk_parts(raw);
    let one = parts.iter().filter(|p| p.content_type == "text/plain").count();
    assert_eq!(one, 1);
}

#[test]
fn lang_detection() {
    assert_eq!(
        detect_tsvector_lang("the quick brown fox is jumping over the lazy dog and it runs"),
        "english"
    );
    assert_eq!(detect_tsvector_lang("der hund ist nicht in der stadt und die katze"), "german");
    assert_eq!(detect_tsvector_lang("hello"), "simple");
    assert_eq!(detect_tsvector_lang("你好世界 这是一个测试"), "simple");
}

#[test]
fn snippet_around_match() {
    let body = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor";
    let s = snippet(body, "consectetur", 20);
    assert!(s.preview.contains("consectetur"));
    assert!(s.preview.starts_with('…'));
    // No match → head of text.
    let s2 = snippet(body, "zebra", 20);
    assert!(!s2.preview.contains('…') || s2.preview.ends_with('…'));
    assert!(s2.preview.starts_with("lorem"));
}