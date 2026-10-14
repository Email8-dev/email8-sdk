// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! JMAP request parsing — the `POST /jmap` envelope, method calls, and
//! result-reference resolution (RFC 8620 §3).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A parsed JMAP request.
#[derive(Debug, Clone, Deserialize)]
pub struct JmapRequest {
    pub using: Vec<String>,
    pub method_calls: Vec<(String, String, Value, String)>,
    #[serde(default)]
    pub created_ids: serde_json::Map<String, Value>,
}

/// A single method call in its typed envelope: `(name, args, call_id)`.
#[derive(Debug, Clone)]
pub struct MethodCall {
    /// e.g. `Email/get`
    pub name: String,
    /// e.g. `Email`
    pub object: String,
    /// e.g. `get`
    pub verb: String,
    pub args: Value,
    pub call_id: String,
}

impl MethodCall {
    /// Split `Foo/get` into (`Foo`, `get`).
    pub fn split(name: &str) -> Option<(String, String)> {
        let (object, verb) = name.split_once('/')?;
        Some((object.to_string(), verb.to_string()))
    }
}

/// Parse the request body, enforcing size and call-count limits.
pub fn parse(body: &[u8]) -> Result<JmapRequest, RequestError> {
    if body.len() > crate::capability::Limits::MAX_SIZE_REQUEST {
        return Err(RequestError::TooLarge);
    }
    let raw: RawJmapRequest = serde_json::from_slice(body).map_err(|_| RequestError::NotJson)?;
    if raw.method_calls.len() > crate::capability::Limits::MAX_CALLS_IN_REQUEST {
        return Err(RequestError::TooManyCalls);
    }
    let method_calls = raw
        .method_calls
        .into_iter()
        .filter_map(|c| {
            let mut it = c.into_iter();
            let name = it.next()?.as_str()?.to_string();
            let args = it.next()?.clone();
            let call_id = it.next()?.as_str()?.to_string();
            Some((name.clone(), name.clone(), args, call_id))
        })
        .collect();
    Ok(JmapRequest {
        using: raw.using,
        method_calls,
        created_ids: raw.created_ids.unwrap_or_default(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawJmapRequest {
    using: Vec<String>,
    method_calls: Vec<Vec<Value>>,
    created_ids: Option<serde_json::Map<String, Value>>,
}

/// Request-level errors → RFC 8620 `problemDetails`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("The request was too large")]
    TooLarge,
    #[error("The request was not valid JSON")]
    NotJson,
    #[error("The request had too many method calls")]
    TooManyCalls,
    #[error("A capability was used that was not in the using array: {0}")]
    UnknownCapability(String),
    #[error("A result reference could not be resolved")]
    UnresolvableReference,
    #[error("The accountId does not match the session")]
    AccountNotFound,
}

impl RequestError {
    pub fn problem_type(&self) -> &'static str {
        match self {
            Self::TooLarge => "urn:ietf:params:jmap:error:limit",
            Self::NotJson => "urn:ietf:params:jmap:error:notRequest",
            Self::TooManyCalls => "urn:ietf:params:jmap:error:limit",
            Self::UnknownCapability(_) => "urn:ietf:params:jmap:error:unknownCapability",
            Self::UnresolvableReference => "urn:ietf:params:jmap:error:cannotCalculateChanges",
            Self::AccountNotFound => "urn:ietf:params:jmap:error:accountNotFound",
        }
    }

    pub fn status(&self) -> u16 {
        400
    }
}

/// A `ResultReference` (RFC 8620 §3.7) — `#`-prefixed pointer to an
/// earlier call's response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReference {
    pub result_of: String,
    pub name: String,
    pub path: String,
}

/// Resolve `#ResultReference` values inside method arguments against the
/// accumulated responses.
pub fn resolve_references(
    args: &mut Value,
    responses: &[(String, Value, String)],
) -> Result<(), RequestError> {
    match args {
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                resolve_value(v, responses)?;
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                resolve_value(v, responses)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_value(v: &mut Value, responses: &[(String, Value, String)]) -> Result<(), RequestError> {
    if let Value::Object(ref mut map) = v {
        if let Some(Value::String(s)) = map.get("resultOf") {
            if let (Some(result_of), Some(name), Some(path)) = (
                map.get("resultOf")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string()),
                map.get("name")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string()),
                map.get("path")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string()),
            ) {
                if !s.starts_with('#') && !result_of.is_empty() {
                    // `#`-prefixed references appear as bare values; the
                    // object form is the canonical representation.
                }
                let found = responses
                    .iter()
                    .find(|(call_id, _, _)| *call_id == result_of)
                    .and_then(|(_, resp, _)| json_pointer(resp, &name, &path));
                *v = found.ok_or(RequestError::UnresolvableReference)?;
                return Ok(());
            }
        }
        for (_k, child) in map.iter_mut() {
            resolve_value(child, responses)?;
        }
    } else if let Value::Array(items) = v {
        for item in items.iter_mut() {
            resolve_value(item, responses)?;
        }
    }
    Ok(())
}

/// Walk `resp[name][path]` (RFC 8620 §3.7 path syntax, `*` wildcard).
fn json_pointer(resp: &Value, name: &str, path: &str) -> Option<Value> {
    // `name` is the response's data key (e.g. `list`); `path` is a slash
    // path possibly containing `*` for array expansion.
    let root = if name.is_empty() {
        resp.clone()
    } else {
        resp.get(name)?.clone()
    };
    let mut cur = root;
    for seg in path.trim_matches('/').split('/') {
        if seg == "*" {
            // Expand arrays: concatenate the remaining path for each item.
            let arr = cur.as_array()?.clone();
            let mut merged = Vec::new();
            for item in arr {
                if let Some(sub) = json_pointer(&item, "", "") {
                    merged.push(sub);
                }
            }
            cur = Value::Array(merged);
            continue;
        }
        if seg.is_empty() {
            continue;
        }
        cur = if let Ok(idx) = seg.parse::<usize>() {
            cur.get(idx)?.clone()
        } else {
            cur.get(seg)?.clone()
        };
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_request() {
        let body = serde_json::to_vec(&json!({
            "using": ["urn:ietf:params:jmap:core"],
            "methodCalls": [
                ["Core/echo", {"call": "hi"}, "c1"]
            ]
        }))
        .unwrap();
        let req = parse(&body).unwrap();
        assert_eq!(req.method_calls.len(), 1);
        assert_eq!(req.method_calls[0].0, "Core/echo");
    }

    #[test]
    fn rejects_too_many_calls() {
        let calls: Vec<_> = (0..40)
            .map(|i| json!(["Core/echo", {}, format!("c{i}")]))
            .collect();
        let body = serde_json::to_vec(&json!({
            "using": ["urn:ietf:params:jmap:core"],
            "methodCalls": calls
        }))
        .unwrap();
        assert!(matches!(parse(&body), Err(RequestError::TooManyCalls)));
    }
}
