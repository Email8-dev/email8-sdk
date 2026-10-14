// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JMAP (RFC 8620) wire protocol library — request parsing, method-call
//! dispatch types, result references, and response building.
//!
//! The Email8:Store service consumes this crate to serve `POST /jmap`.
//! Capabilities cover core + mail + submission + vacation + sieve +
//! groupware (master design §5.3).
//!
//! Design: `email8/design/sentin8-email8-store-technical-design.md` §7.

pub mod capability;
pub mod request;
pub mod response;

pub use capability::*;
pub use request::*;
pub use response::*;
