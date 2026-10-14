// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 vCard — RFC 6350 parse/build (the subset the groupware
//! objects need): FN, N, EMAIL (with TYPE params), ORG, TEL, NOTE,
//! ADR, plus unfolded-line handling shared with the iCalendar parser
//! shape. Contact cards round-trip through the Store's
//! `email8_contact_cards.card` JSONB.

use std::collections::BTreeMap;

/// One parsed vCard property (NAME;PARAM=VAL:value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcardProperty {
    pub name: String,
    pub value: String,
    pub params: Vec<(String, String)>,
}

/// One VCARD component.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Vcard {
    pub properties: Vec<VcardProperty>,
}

impl Vcard {
    /// Parse raw vCard text (one VCARD; the first BEGIN:END block).
    pub fn parse(raw: &str) -> Option<Self> {
        let mut card = Self::default();
        let mut in_card = false;
        for raw_line in raw.lines() {
            // Only the trailing CR is stripped — leading WSP marks a
            // folded continuation and must survive this trim.
            let line = raw_line.trim_end_matches('\r');
            if !in_card {
                if line.eq_ignore_ascii_case("BEGIN:VCARD") {
                    in_card = true;
                }
                continue;
            }
            if line.eq_ignore_ascii_case("END:VCARD") {
                break;
            }
            // Unfold continuations (RFC 6350 §3.2 shares iCal folding):
            // the leading WSP is dropped, one space preserved.
            if (line.starts_with(' ') || line.starts_with('\t')) && !card.properties.is_empty() {
                let cont = line.trim_start_matches([' ', '\t']);
                if let Some(last) = card.properties.last_mut() {
                    if !cont.is_empty() {
                        last.value.push(' ');
                        last.value.push_str(cont);
                    }
                }
                continue;
            }
            if let Some(p) = parse_property(line) {
                card.properties.push(p);
            }
        }
        (!card.properties.is_empty()).then_some(card)
    }

    /// First property value by name (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.value.as_str())
    }

    /// All property values by name.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.properties
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.value.as_str())
            .collect()
    }

    /// EMAIL values (with their TYPE params, e.g. `["work"]`).
    pub fn emails(&self) -> Vec<(String, Vec<String>)> {
        self.properties
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case("EMAIL"))
            .map(|p| {
                let types = p
                    .params
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("TYPE"))
                    .map(|(_, v)| v.to_ascii_lowercase())
                    .collect();
                let addr = p
                    .value
                    .trim()
                    .trim_start_matches("mailto:")
                    .to_ascii_lowercase();
                (addr, types)
            })
            .collect()
    }

    /// All values as a JSON map (the Store's `card` column shape).
    pub fn to_json(&self) -> serde_json::Value {
        let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for p in &self.properties {
            let entry = map
                .entry(p.name.to_ascii_uppercase())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(arr) = entry.as_array_mut() {
                arr.push(serde_json::json!({
                    "value": p.value,
                    "params": p.params.iter()
                        .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
                        .collect::<Vec<_>>(),
                }));
            }
        }
        serde_json::json!(map)
    }
}

fn parse_property(line: &str) -> Option<VcardProperty> {
    // Find the first unquoted ':' — group separator.
    let mut in_quotes = false;
    let mut colon_pos = None;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => {
                colon_pos = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon_pos?;
    let (head, value) = line.split_at(colon);
    let value = &value[1..];
    let mut head_parts = head.split(';');
    let name = head_parts.next()?.trim().to_ascii_uppercase();
    let mut params = Vec::new();
    for p in head_parts {
        if let Some((k, v)) = p.split_once('=') {
            params.push((
                k.trim().to_ascii_uppercase(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    Some(VcardProperty {
        name,
        value: value.to_string(),
        params,
    })
}

/// Build a minimal VCARD wire form (contact-card round-trip).
pub fn build(uid: &str, fn_name: &str, email: &str) -> String {
    format!(
        "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:{fn_name}\r\nEMAIL:{email}\r\nEND:VCARD\r\n",
    )
}

/// Escape one text value (RFC 6350 §3.4: backslash, comma, semicolon,
/// newline).
pub fn escape_text(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:contact-7\r\nFN:Alice Smith\r\n\
        N:Smith;Alice;;;\r\nORG:Example Inc\r\n\
        EMAIL;TYPE=work:alice@example.com\r\n\
        EMAIL;TYPE=home;PREF=1:alice@home.example\r\n\
        TEL;TYPE=cell:+1-555-0100\r\nEND:VCARD\r\n";

    #[test]
    fn parses_core_properties() {
        let card = Vcard::parse(CARD).unwrap();
        assert_eq!(card.get("FN"), Some("Alice Smith"));
        assert_eq!(card.get("ORG"), Some("Example Inc"));
        assert_eq!(card.get("UID"), Some("contact-7"));
    }

    #[test]
    fn emails_extract_with_types() {
        let card = Vcard::parse(CARD).unwrap();
        let emails = card.emails();
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].0, "alice@example.com");
        assert!(emails[0].1.contains(&"work".to_string()));
        assert!(emails[1].1.contains(&"home".to_string()));
    }

    #[test]
    fn folded_values_unfold() {
        let raw = "BEGIN:VCARD\r\nFN:Very Long Name That\r\n Was Folded\r\nEND:VCARD\r\n";
        let card = Vcard::parse(raw).unwrap();
        assert_eq!(card.get("FN"), Some("Very Long Name That Was Folded"));
    }

    #[test]
    fn json_map_round_trips_values() {
        let card = Vcard::parse(CARD).unwrap();
        let j = card.to_json();
        let fn_val = j.get("FN").unwrap().as_array().unwrap()[0]
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(fn_val, "Alice Smith");
        assert!(j.get("EMAIL").is_some());
    }

    #[test]
    fn build_then_parse_roundtrip() {
        let wire = build("u1", "Bob Jones", "bob@corp.example");
        let card = Vcard::parse(&wire).unwrap();
        assert_eq!(card.get("FN"), Some("Bob Jones"));
        assert_eq!(card.emails()[0].0, "bob@corp.example");
    }

    #[test]
    fn non_vcard_input_rejected() {
        assert!(Vcard::parse("Subject: not a card\r\n\r\n").is_none());
    }
}
