// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JMAP capability URNs - the set the Email8:Store server advertises
//! (RFC 8620/8621 + Sieve + groupware).

/// Capability URN constants (RFC 8620 §19 / RFC 8621 §1).
pub mod urn {
    pub const CORE: &str = "urn:ietf:params:jmap:core";
    pub const MAIL: &str = "urn:ietf:params:jmap:mail";
    pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
    pub const VACATION_RESPONSE: &str = "urn:ietf:params:jmap:vacationresponse";
    pub const SIEVE: &str = "urn:ietf:params:jmap:sieve";
    pub const BLOB: &str = "urn:ietf:params:jmap:blob";
    pub const QUOTA: &str = "urn:ietf:params:jmap:quota";
    pub const PRINCIPALS: &str = "urn:ietf:params:jmap:principals";
    pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
    pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
    pub const FILENODE: &str = "urn:ietf:params:jmap:filenode";
    pub const WEBSOCKET: &str = "urn:ietf:params:jmap:websocket";
}

/// Which capability a method call belongs to - enforced against the
/// request's `using` array.
pub fn capability_for_method(object: &str) -> Option<&'static str> {
    match object {
        "Core" => Some(urn::CORE),
        "Email" | "Mailbox" | "Thread" | "SearchSnippet" => Some(urn::MAIL),
        "Identity" | "EmailSubmission" => Some(urn::SUBMISSION),
        "VacationResponse" => Some(urn::VACATION_RESPONSE),
        "SieveScript" => Some(urn::SIEVE),
        "Blob" => Some(urn::BLOB),
        "Quota" => Some(urn::QUOTA),
        "Principal" => Some(urn::PRINCIPALS),
        "Calendar" | "CalendarEvent" | "CalendarEventNotification" => Some(urn::CALENDARS),
        "AddressBook" | "ContactCard" => Some(urn::CONTACTS),
        "FileNode" => Some(urn::FILENODE),
        "PushSubscription" => Some(urn::CORE),
        _ => None,
    }
}

/// Default per-method call limits (RFC 8620 §5.3 recommendations; env rows
/// may override).
pub struct Limits;

impl Limits {
    pub const MAX_CALLS_IN_REQUEST: usize = 32;
    pub const MAX_OBJECTS_GET: usize = 512;
    pub const MAX_OBJECTS_IN_SET: usize = 512;
    pub const MAX_SIZE_REQUEST: usize = 10 * 1024 * 1024;
}
