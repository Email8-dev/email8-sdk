// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8:Gate-scoped contracts — imported as `email8::gate::contracts`
//! (principles §2.1 service nesting: gate-owned `{service}-{kind}` crate).
//!
//! Two modules, both existing *because of* the Gate's port-ownership model
//! (gate design §3.3, §7.2, §7.4; master design §4.2.1):
//!
//! - [`listener_registry`] — the Valkey publisher upstream services (Mta,
//!   Access) use to advertise their OS-ephemeral raw listeners so the Gate
//!   can dial them. This is I/O by nature and lives here rather than in the
//!   shared `email8::contracts` leaf, whose charter is pure serde types
//!   (decision 2026-09-08).
//! - [`proxy_parse`] — PROXY protocol v2 header parsing for the upstream
//!   side (the Gate prepends the header; Mta/Access parse and consume it).

pub mod listener_registry;
pub mod proxy_parse;