// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! # email8 - email8 workspace namespace facade
//!
//! Every email8 crate is named `email8::{leaf}` and is imported through this
//! facade. See `sentin8/design/sentin8-architecture-principles.md` §2.1 and
//! the email8 master design §4.2.1 for the flat-vs-nested rationale.
//!
//! Layout of the re-exports (sections organize the list; the import paths
//! are unchanged):
//!
//! - **Shared vocabulary** - pure serde contracts consumed by every service.
//! - **Gate-scoped** - the one service-nested leaf: I/O + wire parsing that
//!   exists because of the Gate's port-ownership model.
//! - **Wire protocols** - request/response parsers per mail protocol.
//! - **Mail processing** - parse/build pipelines and delivery logic.
//! - **Groupware formats** - calendar/contacts serialization.

// ── Shared vocabulary ──────────────────────────────────────────────────────
pub use email8_contracts as contracts;

// ── Gate-scoped (service nesting per §2.1: package `email8-gate-contracts`) ─
pub mod gate {
    pub use email8_gate_contracts as contracts;
}

// ── Wire protocols ─────────────────────────────────────────────────────────
pub use email8_dav_proto as dav_proto;
pub use email8_imap_proto as imap_proto;
pub use email8_jmap_proto as jmap_proto;
pub use email8_smtp_proto as smtp_proto;

// ── Mail processing ────────────────────────────────────────────────────────
pub use email8_mail_auth as mail_auth;
pub use email8_mail_core as mail_core;
pub use email8_mail_queue as mail_queue;
pub use email8_sieve as sieve;
pub use email8_spam as spam;

// ── Groupware formats ──────────────────────────────────────────────────────
pub use email8_ical as ical;
pub use email8_vcard as vcard;
