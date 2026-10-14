// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! IMAP4rev1/rev2 wire protocol library — server role.
//!
//! Incremental receiver (LITERAL+ aware), typed `Command` model with the
//! core op set (FETCH/STORE/LIST/SELECT/SEARCH parsing) and response
//! builders (untagged data lines, OK/NO/BAD tagged responses).
//!
//! Design: `email8/design/sentin8-email8-access-technical-design.md` §3.

pub mod command;
pub mod receiver;
pub mod response;

pub use command::*;
pub use receiver::*;
pub use response::*;