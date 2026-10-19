// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! `email8:*` event payloads (Sentin8:Bus, inbox-first).
//!
//! Every payload is a **self-contained envelope** - the consumer must be
//! able to run from the payload alone (event-driven execution rules,
//! `AGENTS.md`). Names follow `{vertical}:{service}:{resource}:{operation}`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `email8:smtp:message:received` - a message was accepted into the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReceivedEvent {
    pub env_id: Uuid,
    pub queue_id: Uuid,
    pub return_path: String,
    pub recipients: Vec<QueueRecipientEvent>,
    pub blob_hash: String,
    pub size: i64,
    pub source_flags: u32,
    pub spam_score: Option<f32>,
    pub correlation_id: Option<String>,
}

/// `email8:smtp:recipient:{delivered,failed,deferred}` - per-recipient state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientStatusEvent {
    pub env_id: Uuid,
    pub queue_id: Uuid,
    pub address: String,
    pub status: String,
    pub smtp_reply: Option<String>,
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    pub attempts: i32,
}

/// `email8:smtp:dsn:generated` - a bounce was emitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsnGeneratedEvent {
    pub env_id: Uuid,
    pub queue_id: Uuid,
    pub dsn_queue_id: Uuid,
    pub to_address: String,
    pub for_recipient: Option<String>,
}

/// `email8:smtp:report:*` - an aggregate/failure report window is due.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDueEvent {
    pub env_id: Uuid,
    pub report_kind: String,
    pub report_row_id: i64,
    pub domain: String,
    pub window_end: chrono::DateTime<chrono::Utc>,
}

/// `email8:smtp:message:expired` - a queue message hit TTL/attempts and
/// failed permanently (DLQ candidate; alerts Sentin8:Post).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageExpiredEvent {
    pub env_id: Uuid,
    pub queue_id: Uuid,
    pub return_path: String,
    pub last_error: Option<String>,
}

/// `email8:mail:email:ingested` - local delivery filed into mailbox(es).
/// Drives IMAP IDLE, JMAP push fan-out, and thread-merge workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailIngestedEvent {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub email_id: Uuid,
    pub thread_id: Uuid,
    pub mailboxes: Vec<Uuid>,
    pub imap_uids: Vec<i64>,
    pub change_id: i64,
    pub size: i64,
    pub is_spam: bool,
}

/// `email8:mail:mailbox:{created,updated,deleted}` - mailbox tree changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxChangedEvent {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub mailbox_id: Uuid,
    pub change_id: i64,
}

/// `email8:mail:thread:merge` - multiple candidate threads must be merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMergeEvent {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub surviving_thread_id: Uuid,
    pub merged_thread_ids: Vec<Uuid>,
    pub email_id: Uuid,
}

/// `email8:push:state:changed` - the per-account change cursor advanced;
/// push workers (SSE/WebPush/IDLE) flush to their subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChangedEvent {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collections: Vec<u16>,
    pub change_ids: Vec<i64>,
}

/// `email8:groupware:*` - groupware object changes (iTIP outbound,
/// change-log driven sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupwareChangedEvent {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collection: u16,
    pub document_id: Uuid,
    pub change_id: i64,
    pub operation: String,
}

/// `email8:dkim:key:rotated` - a DKIM key transitioned rotation stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRotatedEvent {
    pub env_id: Uuid,
    pub domain: String,
    pub selector: String,
    pub new_stage: String,
}

/// `email8:spam:sample:recorded` - a training sample landed; the training
/// worker consumes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamSampleRecordedEvent {
    pub env_id: Uuid,
    pub sample_id: i64,
    pub account_id: Option<i64>,
    pub class: String,
    pub blob_hash: String,
}

/// Per-recipient summary embedded in [`MessageReceivedEvent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueRecipientEvent {
    pub address: String,
    pub orcpt: Option<String>,
    pub queue_name: String,
    pub notify_flags: u8,
}
