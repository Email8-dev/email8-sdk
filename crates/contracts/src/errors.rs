// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 error model — vertical error codes registered at enrollment and
//! raised by the services. Platform errors come from `sentin8-errors`;
//! these are mail-domain codes only (zero compile-time vertical knowledge
//! in the platform, architecture-principles.md §4.14).

use serde::{Deserialize, Serialize};

/// Mail-domain error codes (registered into `sentin8_vertical_error_codes`
/// by `--print-registration --section=error_codes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Email8ErrorCode {
    MailboxNotFound,
    EmailNotFound,
    QuotaExceeded,
    BlobQuotaExceeded,
    RcptNotFound,
    RelayDenied,
    SenderAddressRejected,
    DmarcPolicyReject,
    SpamScoreReject,
    Greylisted,
    QueueFull,
    SieveScriptTooLong,
    SieveScriptInvalid,
    SieveScriptExists,
    ThreadNotFound,
    IdentityNotFound,
    DomainNotFound,
    DkimKeyNotFound,
    DuplicateDocument,
}

impl Email8ErrorCode {
    /// Stable error-code string (`error_code` column value).
    pub fn code(self) -> &'static str {
        match self {
            Self::MailboxNotFound => "email8_mailbox_not_found",
            Self::EmailNotFound => "email8_email_not_found",
            Self::QuotaExceeded => "email8_quota_exceeded",
            Self::BlobQuotaExceeded => "email8_blob_quota_exceeded",
            Self::RcptNotFound => "email8_rcpt_not_found",
            Self::RelayDenied => "email8_relay_denied",
            Self::SenderAddressRejected => "email8_sender_address_rejected",
            Self::DmarcPolicyReject => "email8_dmarc_policy_reject",
            Self::SpamScoreReject => "email8_spam_score_reject",
            Self::Greylisted => "email8_greylisted",
            Self::QueueFull => "email8_queue_full",
            Self::SieveScriptTooLong => "email8_sieve_script_too_long",
            Self::SieveScriptInvalid => "email8_sieve_script_invalid",
            Self::SieveScriptExists => "email8_sieve_script_exists",
            Self::ThreadNotFound => "email8_thread_not_found",
            Self::IdentityNotFound => "email8_identity_not_found",
            Self::DomainNotFound => "email8_domain_not_found",
            Self::DkimKeyNotFound => "email8_dkim_key_not_found",
            Self::DuplicateDocument => "email8_duplicate_document",
        }
    }

    /// HTTP status for API surfaces (protocol surfaces map their own
    /// codes — e.g. SMTP `550 5.1.1`).
    pub fn status(self) -> u16 {
        match self {
            Self::MailboxNotFound
            | Self::EmailNotFound
            | Self::RcptNotFound
            | Self::ThreadNotFound
            | Self::IdentityNotFound
            | Self::DomainNotFound
            | Self::DkimKeyNotFound => 404,
            Self::QuotaExceeded | Self::BlobQuotaExceeded | Self::QueueFull => 402,
            Self::RelayDenied | Self::SenderAddressRejected => 403,
            Self::Greylisted => 429,
            Self::DmarcPolicyReject | Self::SpamScoreReject => 422,
            Self::SieveScriptTooLong
            | Self::SieveScriptInvalid
            | Self::SieveScriptExists
            | Self::DuplicateDocument => 400,
        }
    }

    pub fn enum_name(self) -> &'static str {
        match self {
            Self::MailboxNotFound => "Email8MailboxNotFound",
            Self::EmailNotFound => "Email8EmailNotFound",
            Self::QuotaExceeded => "Email8QuotaExceeded",
            Self::BlobQuotaExceeded => "Email8BlobQuotaExceeded",
            Self::RcptNotFound => "Email8RcptNotFound",
            Self::RelayDenied => "Email8RelayDenied",
            Self::SenderAddressRejected => "Email8SenderAddressRejected",
            Self::DmarcPolicyReject => "Email8DmarcPolicyReject",
            Self::SpamScoreReject => "Email8SpamScoreReject",
            Self::Greylisted => "Email8Greylisted",
            Self::QueueFull => "Email8QueueFull",
            Self::SieveScriptTooLong => "Email8SieveScriptTooLong",
            Self::SieveScriptInvalid => "Email8SieveScriptInvalid",
            Self::SieveScriptExists => "Email8SieveScriptExists",
            Self::ThreadNotFound => "Email8ThreadNotFound",
            Self::IdentityNotFound => "Email8IdentityNotFound",
            Self::DomainNotFound => "Email8DomainNotFound",
            Self::DkimKeyNotFound => "Email8DkimKeyNotFound",
            Self::DuplicateDocument => "Email8DuplicateDocument",
        }
    }
}
