// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 mail-auth — SPF, DKIM, DMARC, Authentication-Results.
//!
//! Ports the legacy verification semantics (mail-auth crate family)
//! onto the platform: DNS is injected via the `DnsTxt` trait (the Mta
//! wires a hickory-based resolver at runtime; tests use closures).
//! No mail-domain knowledge leaks into platform crates.

pub mod arc;
pub mod auth_results;
pub mod dkim;
pub mod dmarc;
pub mod spf;

pub use arc::{arc_seal, arc_verify, extract_chain, ArcChainResult, ArcSet};
pub use auth_results::{build_results, received_spf, AuthResult, AuthenticationResults};
pub use dkim::{
    dkim_sign, dkim_verify, DkimKey, DkimSignature, DkimStatus, DkimVerifyOutcome, SingleDkim,
};
pub use dmarc::{dmarc_evaluate, dmarc_lookup, DmarcDisposition, DmarcPolicy, DmarcResult};
pub use spf::{spf_check, spf_domain_owner, SpfParams, SpfResult};

/// DNS TXT lookup interface (async) — implemented by the Mta with
/// DNSSEC-validated hickory; tests use closures.
#[async_trait::async_trait]
pub trait DnsTxt: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, String>;
}

/// A simple closure-based resolver for tests and config-driven lookups.
pub struct FnDnsTxt<F>(pub F);

#[async_trait::async_trait]
impl<F> DnsTxt for FnDnsTxt<F>
where
    F: Fn(&str) -> Result<Vec<String>, String> + Send + Sync,
{
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, String> {
        (self.0)(name)
    }
}
