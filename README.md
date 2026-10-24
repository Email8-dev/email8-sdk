# email8-sdk - Email8 Vertical SDK
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://email8.dev/docs/services/sdk)
[![Website](https://img.shields.io/badge/website-email8.dev-1a73e8.svg)](https://email8.dev/docs/sdk)

## 1. Summary

The Email8 vertical's **shared plane** - the vertical's own
`sentin8-sdk` equivalent (SDD §3.4): the mail protocol stack
(IMAP/SMTP/JMAP/DAV/Sieve), core mail data model, authentication,
queue, and spam-scoring crates that EVERY email8 service (gate, mta,
access, store) links. It stays one workspace because dissolving it
would recreate cross-service repo cycles one level down.

## 2. Crates

| Crate | Purpose |
|---|---|
| `facade` (package `email8`) | Namespace facade - `use email8::imap_proto::…` |
| `crates/mail-core` | Core mail data model (MIME, envelope, mailbox) |
| `crates/mail-auth` | SPF/DKIM/DMARC authentication |
| `crates/mail-queue` | Queue abstractions shared by gate/mta |
| `crates/spam` | Spam scoring |
| `crates/imap-proto` | IMAP protocol |
| `crates/smtp-proto` | SMTP protocol |
| `crates/jmap-proto` | JMAP API protocol |
| `crates/dav-proto` | CalDAV/CardDAV/WebDAV |
| `crates/sieve` | Sieve filtering language |
| `crates/ical` `crates/vcard` | Calendar + contact data formats |
| `crates/gate/contracts` | Gate wire types |
| `crates/contracts` | Shared email8 contracts |

## 3. Consumption

```toml
email8 = { git = "https://github.com/Email8-dev/email8-sdk", tag = "email8-v0.1.0" }
```

The facade pins the platform SDK (`sentin8` - shared plane only,
SDD §2.2).

---

**Architecture & Design:** email8:sdk and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
