// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Shared domain enums — collections, ACL rights, special-use roles,
//! queue statuses, delivery schedules.
//!
//! These replace the legacy u8 `Collection`, the 17-bit `Acl` bitmap, the
//! `SpecialUse` mailbox roles, and the queue `Status`/schedule types.
//! Values keep the legacy *semantics* (store design §2) with PostgreSQL
//! native representations.

use serde::{Deserialize, Serialize};

/// Data collection (legacy `Collection` enum). The u16 values are stable
/// wire identifiers used in the change log and ACL grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum Collection {
    Email = 0,
    Mailbox = 1,
    Thread = 2,
    Identity = 3,
    EmailSubmission = 4,
    SieveScript = 5,
    PushSubscription = 6,
    Principal = 7,
    Calendar = 8,
    CalendarEvent = 9,
    AddressBook = 10,
    ContactCard = 11,
    FileNode = 12,
    CalendarEventNotification = 13,
}

impl Collection {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0 => Self::Email,
            1 => Self::Mailbox,
            2 => Self::Thread,
            3 => Self::Identity,
            4 => Self::EmailSubmission,
            5 => Self::SieveScript,
            6 => Self::PushSubscription,
            7 => Self::Principal,
            8 => Self::Calendar,
            9 => Self::CalendarEvent,
            10 => Self::AddressBook,
            11 => Self::ContactCard,
            12 => Self::FileNode,
            13 => Self::CalendarEventNotification,
            _ => return None,
        })
    }

    /// JMAP state-type name (`{Type}/changes`), identical to the legacy
    /// `SyncCollection` names.
    pub fn state_name(self) -> &'static str {
        match self {
            Self::Email => "Email",
            Self::Mailbox => "Mailbox",
            Self::Thread => "Thread",
            Self::Identity => "Identity",
            Self::EmailSubmission => "EmailSubmission",
            Self::SieveScript => "SieveScript",
            Self::PushSubscription => "PushSubscription",
            Self::Principal => "Principal",
            Self::Calendar => "Calendar",
            Self::CalendarEvent => "CalendarEvent",
            Self::AddressBook => "AddressBook",
            Self::ContactCard => "ContactCard",
            Self::FileNode => "FileNode",
            Self::CalendarEventNotification => "CalendarEventNotification",
        }
    }
}

/// ACL right bits (legacy `types::acl::Acl` — same bit assignments).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl(pub u32);

impl Acl {
    pub const READ: u32 = 1 << 0;
    pub const MODIFY: u32 = 1 << 1;
    pub const DELETE: u32 = 1 << 2;
    pub const READ_ITEMS: u32 = 1 << 3;
    pub const ADD_ITEMS: u32 = 1 << 4;
    pub const MODIFY_ITEMS: u32 = 1 << 5;
    pub const REMOVE_ITEMS: u32 = 1 << 6;
    pub const CREATE_CHILD: u32 = 1 << 7;
    pub const SHARE: u32 = 1 << 8;
    pub const SUBMIT: u32 = 1 << 9;
    pub const SCHEDULING_READ_FREE_BUSY: u32 = 1 << 10;
    pub const SCHEDULING_INVITE: u32 = 1 << 11;
    pub const SCHEDULING_REPLY: u32 = 1 << 12;
    pub const MODIFY_ITEMS_OWN: u32 = 1 << 13;
    pub const MODIFY_PRIVATE_PROPERTIES: u32 = 1 << 14;
    pub const MODIFY_RSVP: u32 = 1 << 15;

    pub fn has(&self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

/// Mailbox special-use role (legacy `SpecialUse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpecialUse {
    Inbox,
    Trash,
    Junk,
    Drafts,
    Sent,
    Archive,
    Memos,
    Scheduled,
    Snoozed,
}

impl SpecialUse {
    /// Fixed mailbox ids for the bootstrap set (legacy `email::mailbox`
    /// constants INBOX=0 … ARCHIVE=5).
    pub const INBOX_ID: i64 = 0;
    pub const TRASH_ID: i64 = 1;
    pub const JUNK_ID: i64 = 2;
    pub const DRAFTS_ID: i64 = 3;
    pub const SENT_ID: i64 = 4;
    pub const ARCHIVE_ID: i64 = 5;
}

/// Queue recipient status (legacy `queue::Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientStatus {
    Scheduled,
    Completed,
    PermanentFailure,
    TemporaryFailure,
}

/// Virtual queue names (legacy `QueueName` defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueName {
    Local,
    Remote,
    Dsn,
    Report,
}

impl QueueName {
    /// Default retry schedules — seconds after each successive attempt
    /// (legacy defaults from `common/src/manager/defaults.rs`).
    pub fn retry_schedule(self) -> &'static [u32] {
        match self {
            Self::Local | Self::Remote => &[120, 300, 600, 900, 1800, 3600, 7200, 86_400, 259_200],
            Self::Dsn => &[900, 1800, 3600, 7200],
            Self::Report => &[1800, 3600, 7200],
        }
    }

    /// Default DSN notification schedule offsets (seconds).
    pub fn notify_schedule(self) -> &'static [u32] {
        match self {
            Self::Local | Self::Remote => &[86_400, 259_200],
            _ => &[],
        }
    }

    /// Default expiry (seconds) — TTL for local/remote, attempt counts for
    /// dsn/report queues are enforced by the schedule length instead.
    pub fn expiry_ttl(self) -> Option<u64> {
        match self {
            Self::Local | Self::Remote => Some(3 * 24 * 3600),
            _ => None,
        }
    }
}

/// DKIM key rotation stage (legacy `DkimRotationStage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DkimStage {
    Pending,
    Active,
    Retiring,
    Retired,
}

/// Message source flags — set on queued messages to drive policy
/// (auth-results, spam filtering, DKIM signing).
pub mod message_source {
    pub const AUTHENTICATED: u32 = 1 << 0;
    pub const UNAUTHENTICATED: u32 = 1 << 1;
    pub const DMARC_PASS: u32 = 1 << 2;
    pub const AUTOGENERATED: u32 = 1 << 3;
    pub const DSN: u32 = 1 << 4;
    pub const REPORT: u32 = 1 << 5;
    pub const VACATION: u32 = 1 << 6;
}
