// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JMAP response construction — `JmapResponse` builder, per-call error
//! envelopes, and the RFC 8620 problem-details top-level error.

use serde_json::{json, Map, Value};

/// A complete JMAP response: `methodResponses` + session `createdIds`.
#[derive(Debug, Clone, Default)]
pub struct JmapResponse {
    pub method_responses: Vec<(String, Value, String)>,
    pub created_ids: Map<String, Value>,
    /// Top-level error (RFC 8620 §3.6.1) — when set, `methodResponses` is
    /// replaced by `problemDetails`.
    pub problem: Option<Value>,
}

impl JmapResponse {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a successful method response: `["Foo/get", result, callId]`.
    pub fn push(&mut self, name: impl Into<String>, result: Value, call_id: impl Into<String>) {
        self.method_responses.push((name.into(), result, call_id.into()));
    }

    /// Append a per-call error: `["error", {...}, callId]`.
    pub fn push_error(&mut self, description: impl AsRef<str>, call_id: impl Into<String>) {
        let payload = json!({
            "type": "error",
            "description": description.as_ref(),
        });
        self.method_responses.push(("error".into(), payload, call_id.into()));
    }

    /// Record a `createdIds` mapping from a Set/Import response.
    pub fn merge_created_ids(&mut self, created: Value) {
        if let Value::Object(map) = created {
            for (k, v) in map {
                self.created_ids.insert(k, v);
            }
        }
    }

    /// Serialize the wire body.
    pub fn to_json(&self) -> Value {
        if let Some(problem) = &self.problem {
            let mut m = problem.as_object().cloned().unwrap_or_default();
            m.insert("type".into(), json!("error"));
            return Value::Object(m);
        }
        json!({
            "methodResponses": self.method_responses.iter()
                .map(|(n, r, c)| json!([n, r, c]))
                .collect::<Vec<_>>(),
            "createdIds": Value::Object(self.created_ids.clone()),
        })
    }
}

/// Standard per-call error payloads.
pub fn error_invalid_properties(path: &str, description: &str) -> Value {
    json!({
        "type": "invalidProperties",
        "properties": [path],
        "description": description,
    })
}

pub fn error_not_found() -> Value {
    json!({ "type": "notFound" })
}

pub fn error_forbidden(description: &str) -> Value {
    json!({ "type": "forbidden", "description": description })
}

pub fn error_server_fail(description: &str) -> Value {
    json!({ "type": "serverFail", "description": description })
}

pub fn error_limit(description: &str) -> Value {
    json!({ "type": "limit", "description": description })
}

/// `{Type}/get` success result.
pub fn get_result(list: Value, state: &str, not_found: Value) -> Value {
    json!({ "list": list, "state": state, "notFound": not_found })
}

/// `{Type}/changes` success result.
pub fn changes_result(
    old_state: &str,
    new_state: &str,
    created: Value,
    updated: Value,
    destroyed: Value,
    has_more: bool,
) -> Value {
    json!({
        "oldState": old_state,
        "newState": new_state,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "hasMoreChanges": has_more,
    })
}

/// `{Type}/set` success result (only present keys serialized).
pub fn set_result(fields: Map<String, Value>) -> Value {
    Value::Object(fields)
}

/// `{Type}/query` success result.
pub fn query_result(ids: Value, position: i64, total: i64, limit: i64) -> Value {
    json!({
        "ids": ids,
        "position": position,
        "total": total,
        "canCalculateChanges": false,
        "limit": limit,
    })
}

/// `Blob/upload` success result.
pub fn upload_result(account_id: &str, blob_id: &str, kind: &str, size: i64) -> Value {
    json!({
        "accountId": account_id,
        "blobId": blob_id,
        "type": kind,
        "size": size,
    })
}

/// Core/echo — mirrors the arguments back.
pub fn echo(args: serde_json::Value) -> Value {
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_serializes() {
        let mut r = JmapResponse::new();
        r.push("Core/echo", json!({"hello": "world"}), "c1");
        let v = r.to_json();
        assert_eq!(
            v["methodResponses"][0],
            json!(["Core/echo", {"hello": "world"}, "c1"])
        );
    }

    #[test]
    fn problem_replaces_responses() {
        let mut r = JmapResponse::new();
        r.problem = Some(json!({"title": "Request too large"}));
        let v = r.to_json();
        assert!(v.get("methodResponses").is_none());
        assert_eq!(v["type"], "error");
    }
}