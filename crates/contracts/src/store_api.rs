// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8:Store internal data API DTOs.
//!
//! Email8:Store is the only writer of the mail tables; Mta, Access and
//! Apps call these typed endpoints over the service-to-service surface
//! (M2M-authenticated). This is the *justified* sync surface — callers
//! need the returned values in the same request (master design §4.8).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Principals / provisioning ────────────────────────────────────────────

/// Resolve an address to a principal (legacy `rcpt_resolve` core).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ResolveAddressRequest {
    pub env_id: Uuid,
    pub address: String,
    /// Apply sub-addressing (`user+tag@domain`) before lookup.
    #[serde(default = "default_true")]
    pub sub_addressing: bool,
}

fn default_true() -> bool {
    true
}

/// Resolution outcome (legacy `RcptResolution`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolvedAddress {
    /// A local principal account.
    Account {
        account_id: Uuid,
        name: String,
        /// Effective delivery address after sub-addressing/alias rewrite.
        address: String,
    },
    /// A mailing list/group — expand to members.
    Group {
        group_id: Uuid,
        members: Vec<String>,
    },
    /// The env's catch-all target.
    CatchAll { account_id: Uuid, address: String },
    /// Not local — relay decision belongs to the caller (env relay policy).
    External { address: String },
    /// Unknown local address.
    Invalid { address: String },
}

// ── Mailbox ops ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MailboxDto {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub role: Option<String>,
    pub parent_id: Option<Uuid>,
    pub sort_order: i32,
    pub uid_validity: i64,
    pub uid_next: i64,
    pub is_subscribed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateMailboxRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub role: Option<String>,
    pub parent_id: Option<Uuid>,
}

// ── Email ingest (local delivery, APPEND, JMAP import) ───────────────────

/// Raw message ingestion — the single entry point Mta local delivery,
/// IMAP APPEND and JMAP Email/import all funnel through.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestMessage {
    pub env_id: Uuid,
    pub account_id: Uuid,
    /// Storage content-address key for the raw message bytes.
    pub blob_hash: String,
    pub size: i64,
    /// Source metadata for the change log + spam overrides.
    pub source: String,
    pub source_flags: u32,
    pub delivered_to: Option<String>,
    /// Mailbox ids to file into; defaults to INBOX.
    #[serde(default)]
    pub mailboxes: Vec<Uuid>,
    /// Pre-computed spam percentage (0-100) — ≥50 re-files to JUNK.
    pub spam_percentage: Option<f32>,
    /// Skip spam re-file when the sender is a known-ham address.
    #[serde(default)]
    pub ham_override: bool,
    /// Idempotency key — (blob_hash, mailbox set, envelope) dedup.
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestedEmail {
    pub email_id: Uuid,
    pub account_id: Uuid,
    pub thread_id: Uuid,
    pub mailboxes: Vec<MailboxUid>,
    pub change_id: i64,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MailboxUid {
    pub mailbox_id: Uuid,
    pub imap_uid: i64,
}

// ── Changelog / state ────────────────────────────────────────────────────

/// A change-log window query (JMAP `/changes`, IMAP QRESYNC since).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangesSinceRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collection: u16,
    pub since_change_id: Option<i64>,
    pub max_changes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangesSinceResponse {
    pub old_state: i64,
    pub new_state: i64,
    pub has_more_changes: bool,
    pub created: Vec<Uuid>,
    pub updated: Vec<Uuid>,
    pub destroyed: Vec<Uuid>,
}

// ── Submission (JMAP EmailSubmission / SMTP AUTH submit both land here) ──

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubmitRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    /// Sentin8:Auth user `sub` — re-verified by Mta from claims.
    pub user_sub: Uuid,
    pub return_path: String,
    pub recipients: Vec<String>,
    pub blob_hash: String,
    pub size: i64,
    /// Delayed send (`sendAt`).
    pub hold_until: Option<DateTime<Utc>>,
    pub source: String,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubmitResponse {
    pub queue_id: Uuid,
    /// Earliest due event (retry/notify/expiry) — informational.
    pub next_event_at: Option<DateTime<Utc>>,
}

// ── Blob quota ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BlobQuotaCheck {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BlobQuotaVerdict {
    pub allowed: bool,
    pub used_bytes: i64,
    pub quota_bytes: Option<i64>,
}
