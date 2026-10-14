// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 shared contracts — event payloads, DTOs, error codes, enums.
//!
//! This crate is the single vocabulary shared by the four Email8 services
//! (Mta, Store, Access, Apps) and by any future consumer of `email8:*`
//! events. It contains zero I/O and zero platform dependencies — only
//! serde types, per the typed-contracts principle
//! (`sentin8-architecture-principles.md` §4.2).
//!
//! Gate-scoped contracts (Valkey listener-registry publisher, PROXY v2
//! parsing) live in `email8::gate::contracts` (package `email8-gate-contracts`)
//! — this crate carries no I/O (master design §4.2.1, decision 2026-09-08).
//!
//! Design: `email8/design/sentin8-email8-technical-design.md` §4.6.

pub mod enums;
pub mod errors;
pub mod events;
pub mod queue;
pub mod store_api;

pub use enums::*;
pub use errors::*;
pub use events::*;
pub use queue::*;
pub use store_api::*;
