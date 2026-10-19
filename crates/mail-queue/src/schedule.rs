// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Retry/notify/expiry schedule resolution - the legacy `QueueStrategy`
//! tables. All values are seconds; per-strategy env overrides are read
//! by the Mta (config rows), not here.

use chrono::{DateTime, Utc};

/// The virtual queue a recipient lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKind {
    Local,
    Remote,
    Dsn,
    Report,
}

impl QueueKind {
    /// Retry schedule (seconds from the failed attempt).
    pub fn retry_schedule(self) -> &'static [i64] {
        match self {
            QueueKind::Local | QueueKind::Remote => {
                &[120, 300, 600, 900, 1800, 3600, 7200, 86400, 259_200]
            }
            QueueKind::Dsn => &[900, 1800, 3600, 7200],
            QueueKind::Report => &[1800, 3600, 7200],
        }
    }

    /// Notify schedule for DSN delay warnings (seconds since enqueue).
    pub fn notify_schedule(self) -> &'static [i64] {
        match self {
            QueueKind::Local | QueueKind::Remote => &[86400, 259_200],
            _ => &[],
        }
    }

    /// Message TTL (seconds) - expiry sweep boundary.
    pub fn expiry_ttl(self) -> Option<i64> {
        match self {
            QueueKind::Local | QueueKind::Remote => Some(3 * 86400),
            // Attempt-counted queues expire via attempts, not TTL.
            QueueKind::Dsn | QueueKind::Report => None,
        }
    }

    /// Max attempts before the queue gives up.
    pub fn max_attempts(self) -> usize {
        match self {
            QueueKind::Local | QueueKind::Remote => self.retry_schedule().len(),
            QueueKind::Dsn => 10,
            QueueKind::Report => 8,
        }
    }
}

/// The next retry instant for `attempts` prior failures.
pub fn next_retry_at(kind: QueueKind, from: &DateTime<Utc>, attempts: u32) -> DateTime<Utc> {
    let table = kind.retry_schedule();
    let idx = attempts as usize;
    let secs = if table.is_empty() {
        3600
    } else {
        table[idx.min(table.len() - 1)]
    };
    *from + chrono::Duration::seconds(secs)
}

/// Whether a delay-notification is due (never re-sent twice: the caller
/// tracks `notified` state).
pub fn notify_due_at(kind: QueueKind, enqueued_at: &DateTime<Utc>) -> Option<DateTime<Utc>> {
    kind.notify_schedule()
        .first()
        .map(|s| *enqueued_at + chrono::Duration::seconds(*s))
}

/// Resolve the expires_at boundary for a queue message.
pub fn resolve_expiry(kind: QueueKind, enqueued_at: &DateTime<Utc>) -> Option<DateTime<Utc>> {
    kind.expiry_ttl()
        .map(|ttl| *enqueued_at + chrono::Duration::seconds(ttl))
}

/// Classify a remote SMTP reply into (retryable, done).
/// 2xx → done; 4xx → retry; 5xx → permanent fail. Anything else
/// (malformed) → retry conservatively.
pub fn classify_reply(code: u16) -> Class {
    match code {
        200..=299 => Class::Completed,
        400..=499 => Class::Temporary,
        500..=599 => Class::Permanent,
        _ => Class::Temporary,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Completed,
    Temporary,
    Permanent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_attempts_table() {
        assert_eq!(QueueKind::Dsn.retry_schedule(), &[900, 1800, 3600, 7200]);
        assert_eq!(QueueKind::Dsn.max_attempts(), 10);
        assert_eq!(QueueKind::Dsn.expiry_ttl(), None);
    }

    #[test]
    fn reply_classification() {
        assert_eq!(classify_reply(250), Class::Completed);
        assert_eq!(classify_reply(451), Class::Temporary);
        assert_eq!(classify_reply(550), Class::Permanent);
        assert_eq!(classify_reply(0), Class::Temporary);
    }
}
