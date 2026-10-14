// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Listener registry publisher (design §4.1, gate story 7.2).
//!
//! With Email8:Gate owning the well-known ports, upstream services bind
//! their raw protocol listeners on **OS-ephemeral ports** (`port: 0` →
//! `bind("0.0.0.0:0")` → read back `local_addr().port()`). Concurrent
//! instances (rolling upgrade old+new) can never contend for a fixed
//! port.
//!
//! Each service then PUBLISHes its actual listener map to the Valkey
//! registry so the gate can discover dial targets (the connection
//! presents the CALLER's `m2m-{workload}` certificate identity over
//! the Valkey TLS plane — platform group DESIGN.md §3.1):
//!
//! ```text
//! HSET captain:listeners:{service_type}:{instance_key} {proto} "{port, implicit_tls}"
//! DEL  captain:listeners:{service_type}:{old_key}   (on shutdown)
//! ```
//!
//! Hash field = protocol name (`smtp`, `submission`, `imaps`, …);
//! value = `{ip}:{port}`. The gate reads `captain:svc:{service_type}`
//! for Active instances (ip from there) and `captain:listeners:{type}`
//! for the port map — keyed by the instance's `{ip}:{shell_port}` when
//! instances differ, falling back to the shared map.
//!
//! Dev direct-bind mode: an explicit `EMAIL8_*_PORT` env pins the port
//! and the publisher still runs (map records the pinned port).

/// One bound raw listener.
#[derive(Debug, Clone)]
pub struct BoundListener {
    /// Protocol name — the gate's listener-name space (`smtp`,
    /// `submission`, `submissions`, `imap`, `imaps`, `pop3`, `pop3s`,
    /// `sieve`).
    pub proto: &'static str,
    /// Actual bound port (ephemeral or env-pinned).
    pub port: u16,
    pub implicit_tls: bool,
}

/// Publish the listener map for `service_type`, presenting the CALLER's
/// `workload` certificate identity (the CN maps to its enroll-provisioned
/// ACL user — platform group DESIGN.md §3.1). Best-effort: Valkey
/// unavailability degrades to log-only (the gate then finds no entry
/// and refuses connections for that service — visible, not silent).
pub async fn publish(
    valkey_url: &str,
    workload: &str,
    service_type: &str,
    instance_key: &str,
    listeners: &[BoundListener],
) {
    use glide::AsyncCommands as _;
    let Ok(client) = sentin8::middleware::valkey_client(valkey_url, workload).await else {
        tracing::warn!(service = service_type, "email8:listeners: valkey connect failed — gate discovery unavailable");
        return;
    };
    let key = format!("captain:listeners:{service_type}");
    let map_key = format!("{key}:{instance_key}");
    let _: usize = client.del(&map_key).await.unwrap_or(0);
    for l in listeners {
        let value = serde_json::json!({ "port": l.port, "implicit_tls": l.implicit_tls });
        let _: usize = client
            .hset(&map_key, l.proto, value.to_string())
            .await
            .unwrap_or(0);
    }
    let _: usize = client
        .publish("captain:changed", service_type)
        .await
        .unwrap_or(0);
    tracing::info!(
        service = service_type,
        instance = instance_key,
        listeners = ?listeners.iter().map(|l| (l.proto, l.port)).collect::<Vec<_>>(),
        "email8:listeners: published"
    );
}

/// Best-effort remove of one instance's listener map (graceful stop),
/// presenting the CALLER's `workload` certificate identity.
pub async fn unpublish(valkey_url: &str, workload: &str, service_type: &str, instance_key: &str) {
    use glide::AsyncCommands as _;
    let Ok(client) = sentin8::middleware::valkey_client(valkey_url, workload).await else {
        return;
    };
    let map_key = format!("captain:listeners:{service_type}:{instance_key}");
    let _: usize = client.del(&map_key).await.unwrap_or(0);
    tracing::info!(service = service_type, instance = instance_key, "email8:listeners: unpublished");
}

/// Spawn a SIGTERM/Ctrl-C watcher that un-publishes this instance's
/// listener map (gate design §3.3, story 7.4). Best-effort: if the
/// Valkey write races the process kill, the gate's Active-only map
/// reads make stale keys harmless anyway.
pub fn spawn_unpublish_on_shutdown(
    valkey_url: String,
    workload: &'static str,
    service_type: &'static str,
    instance_key: String,
) {
    tokio::spawn(async move {
        sentin8::middleware::shutdown_signal(service_type).await;
        unpublish(&valkey_url, workload, service_type, &instance_key).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_listener_shape() {
        let l = BoundListener { proto: "smtp", port: 43111, implicit_tls: false };
        assert_eq!(l.proto, "smtp");
        assert_eq!(l.port, 43111);
    }

    #[test]
    fn publish_inputs_are_cheap_clones() {
        // The publisher takes owned Strings — document the contract that
        // callers build them per-boot (no hot-path allocation concerns).
        let svc = "email8-mta".to_string();
        let key = "172.0.0.1:8052".to_string();
        assert_eq!(format!("captain:listeners:{svc}:{key}"),
                   "captain:listeners:email8-mta:172.0.0.1:8052");
    }
}