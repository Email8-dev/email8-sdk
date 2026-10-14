// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 mail core — RFC 5322/MIME parsing, threading, envelope and
//! preview extraction.
//!
//! This crate owns the pure functions every service needs: given raw
//! message bytes, produce the parsed metadata the Store persists and the
//! protocol surfaces render. No I/O, no platform dependencies.
//!
//! Design: `email8/design/sentin8-email8-store-technical-design.md` §4–5.

pub mod fts;
pub mod message;
pub mod mime;
pub mod threading;

pub use fts::*;
pub use message::*;
pub use mime::*;
pub use threading::*;