// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Queue wire types - the message record and recipient rows shared
//! between the Mta queue manager and admin/RFW views (queue design §3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A queued message as persisted in `email8_queue_messages`.
///
/// The legacy rkyv-serialized `queue::Message` becomes a row plus
/// normalized recipient rows; this DTO is the wire form used by the
/// internal data API and the admin queue viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMessage {
    pub id: Uuid,
    pub env_id: Uuid,
    pub return_path: String,
    pub blob_hash: String,
    pub size: i64,
    pub priority: i32,
    pub source_flags: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

/// A per-recipient row (`email8_queue_recipients`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueRecipient {
    pub id: i64,
    pub message_id: Uuid,
    pub address: String,
    pub orcpt: Option<String>,
    pub queue_name: String,
    pub status: String,
    pub notify_flags: u8,
    pub attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub next_notify_at: Option<DateTime<Utc>>,
    pub last_reply: Option<String>,
    pub dsn_sent_at: Option<DateTime<Utc>>,
}

/// Queue due-event kinds - what wakes the manager loop
/// (`email8_queue_events.due_at` + `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueEventKind {
    /// Retry a deferred recipient (or first attempt).
    Delivery,
    /// Send/advance a DSN notification.
    Dsn,
    /// Expire the message (TTL / attempts exhausted → terminal).
    Expiry,
}

/// DSN disposition (RFC 3464 NOTIFY values).
pub mod notify {
    pub const NEVER: u8 = 0b0001;
    pub const SUCCESS: u8 = 0b0010;
    pub const FAILURE: u8 = 0b0100;
    pub const DELAY: u8 = 0b1000;
}
