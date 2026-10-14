// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 queue math — schedule resolution (retry/notify/expiry), DSN
//! (RFC 3464) construction, and SMTP reply classification. Pure
//! functions over the queue tables; persistence lives in the Mta
//! service. Mirrors legacy `QueueStrategy`/`DSN` semantics.

pub mod dsn;
pub mod schedule;

pub use dsn::{build_dsn, DsnRecipient, DsnType};
pub use schedule::{next_retry_at, notify_due_at, resolve_expiry, QueueKind};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_schedule_matches_legacy() {
        // First three attempts: 2m, 5m, 10m from the attempt boundary.
        let base = chrono::Utc::now();
        assert_eq!(
            next_retry_at(QueueKind::Remote, &base, 0) - base,
            chrono::Duration::seconds(120)
        );
        assert_eq!(
            next_retry_at(QueueKind::Remote, &base, 1) - base,
            chrono::Duration::seconds(300)
        );
        assert_eq!(
            next_retry_at(QueueKind::Remote, &base, 2) - base,
            chrono::Duration::seconds(600)
        );
        // Beyond the table: last entry (3d).
        assert_eq!(
            next_retry_at(QueueKind::Remote, &base, 40) - base,
            chrono::Duration::seconds(259_200)
        );
    }
}