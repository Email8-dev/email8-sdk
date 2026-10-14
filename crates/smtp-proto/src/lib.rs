// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! SMTP/LMTP wire protocol library — server role.
//!
//! Incremental line-based receiver (bytes are fed from the socket; commands
//! complete on CRLF), a typed `Command` model, and an SMTP reply builder
//! with the standard enhanced status codes used by the inbound pipeline.
//!
//! Design: `email8/design/sentin8-email8-mta-technical-design.md` §2.1.

pub mod command;
pub mod receiver;
pub mod reply;

pub use command::*;
pub use receiver::*;
pub use reply::*;