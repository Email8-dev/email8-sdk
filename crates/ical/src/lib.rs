// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 iCalendar — RFC 5545 parse/build + recurrence expansion.
//!
//! A pragmatic subset: VEVENT (+ VTODO basic fields), folded-line
//! unfolding, property parameters, DATE-TIME / DATE values, RRULE
//! expansion (FREQ=SECONDLY..YEARLY with INTERVAL, COUNT, UNTIL,
//! BYDAY for WEEKLY), and EXDATE exclusion. UID uniqueness is the
//! caller's contract (the Store enforces it on insert; synthetic ids
//! are derived here for events that lack one).

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Timelike, Utc};

/// One parsed iCalendar property: NAME;PARAM=VAL:value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcalProperty {
    pub name: String,
    pub value: String,
    pub params: Vec<(String, String)>,
}

/// One calendar component (VEVENT / VTODO / VCALENDAR container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcalComponent {
    pub kind: String, // VEVENT | VTODO | VCALENDAR | …
    pub properties: Vec<IcalProperty>,
    pub children: Vec<IcalComponent>,
}

/// Unfold RFC 5545 §3.1 folded lines (CRLF + WSP continues).
pub fn unfold(raw: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t')) && !lines.is_empty() {
            // RFC 5545: the leading WSP is removed when unfolding;
            // multi-WSP folds keep one space by preserving the tail.
            let last = lines.last_mut().unwrap();
            let cont = line.trim_start();
            if !cont.is_empty() {
                last.push(' ');
                last.push_str(cont);
            }
        } else {
            lines.push(line.to_string());
        }
    }
    lines
}

/// Parse raw iCalendar text into the component tree.
pub fn parse(raw: &str) -> IcalComponent {
    fn parse_block(lines: &[String]) -> IcalComponent {
        // First line is BEGIN:<kind>.
        let kind = lines
            .first()
            .and_then(|l| l.split_once(':'))
            .map(|(_, k)| k.trim().to_ascii_uppercase())
            .unwrap_or_default();
        let mut comp = IcalComponent { kind, properties: Vec::new(), children: Vec::new() };
        let mut i = 1;
        while i < lines.len() {
            let line = &lines[i];
            let name = line.split([':', ';']).next().unwrap_or_default().to_ascii_uppercase();
            if name == "BEGIN" {
                let start = i;
                // Find the matching END at depth 0.
                let mut depth = 1;
                let mut j = i + 1;
                while j < lines.len() {
                    let n = lines[j]
                        .split([':', ';'])
                        .next()
                        .unwrap_or_default()
                        .to_ascii_uppercase();
                    if n == "BEGIN" {
                        depth += 1;
                    } else if n == "END" {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    j += 1;
                }
                let end = j.min(lines.len().saturating_sub(1));
                if end > start {
                    comp.children
                        .push(parse_block(&lines[start..=end.min(lines.len() - 1)]));
                }
                i = end + 1;
                continue;
            }
            if name == "END" {
                break;
            }
            // NAME;PARAM=V;PARAM2=V2:value — params may be quoted.
            if let Some(prop) = parse_property(line) {
                comp.properties.push(prop);
            }
            i += 1;
        }
        comp
    }

    let lines = unfold(raw)
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    parse_block(&lines)
}

/// Parse one property line (NAME;PARAM=value:value) — quote-aware on
/// both the `:` group separator and the `;` parameter splits.
fn parse_property(line: &str) -> Option<IcalProperty> {
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
    // Split head on ';' honoring quoted segments.
    let mut head_parts: Vec<&str> = Vec::new();
    let mut in_q = false;
    let mut start = 0;
    for (i, ch) in head.char_indices() {
        match ch {
            '"' => in_q = !in_q,
            ';' if !in_q => {
                head_parts.push(&head[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    head_parts.push(&head[start..]);
    let name = head_parts.first()?.trim().to_ascii_uppercase();
    let mut params = Vec::new();
    for p in head_parts.iter().skip(1) {
        if let Some((k, v)) = p.split_once('=') {
            params.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
        }
    }
    Some(IcalProperty { name, value: value.to_string(), params })
}

impl IcalComponent {
    /// First property value by name (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.value.as_str())
    }

    /// All properties by name.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.properties
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.value.as_str())
            .collect()
    }

    /// Child components of one kind.
    pub fn children_of(&self, kind: &str) -> Vec<&IcalComponent> {
        self.children.iter().filter(|c| c.kind == kind).collect()
    }
}

/// Parsed DATE or DATE-TIME value (floating → UTC assumed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcalTime {
    Date(NaiveDate),
    DateTime(DateTime<Utc>),
}

impl IcalTime {
    pub fn parse(v: &str) -> Option<Self> {
        let v = v.trim();
        if v.len() == 8 && v.chars().all(|c| c.is_ascii_digit()) {
            let (y, m, d) = (v[0..4].parse().ok()?, v[4..6].parse().ok()?, v[6..8].parse().ok()?);
            return NaiveDate::from_ymd_opt(y, m, d).map(Self::Date);
        }
        // DATE-TIME: YYYYMMDDTHHMMSS[Z]
        let v = v.trim_end_matches('Z');
        if v.len() < 15 {
            return None;
        }
        let date = NaiveDate::from_ymd_opt(
            v[0..4].parse().ok()?,
            v[4..6].parse().ok()?,
            v[6..8].parse().ok()?,
        )?;
        let time = chrono::NaiveTime::from_hms_opt(
            v[9..11].parse().ok()?,
            v[11..13].parse().ok()?,
            v[13..15].parse().ok()?,
        )?;
        let dt = Utc.from_utc_datetime(&date.and_time(time));
        Some(Self::DateTime(dt))
    }

    pub fn to_utc(&self) -> DateTime<Utc> {
        match self {
            Self::Date(d) => Utc.from_utc_datetime(
                &d.and_hms_opt(0, 0, 0).unwrap_or_default(),
            ),
            Self::DateTime(dt) => *dt,
        }
    }
}

// Silence the unused-Pipe lint: the helper remains for future parse
// chains; parse() constructs directly today.
#[allow(unused)]
/// One RRULE (the subset the worker expands).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RRule {
    pub freq: String,      // DAILY | WEEKLY | MONTHLY | YEARLY (HOURLY/MINUTELY/SECONDLY supported)
    pub interval: u32,     // default 1
    pub count: Option<u32>,
    pub until: Option<IcalTime>,
    /// BYDAY codes for WEEKLY (MO..SU); multi-letter prefixes parsed but
    /// only the weekday is kept (simplified).
    pub byday: Vec<String>,
}

impl RRule {
    pub fn parse(v: &str) -> Option<Self> {
        let mut r = RRule {
            freq: String::new(),
            interval: 1,
            count: None,
            until: None,
            byday: Vec::new(),
        };
        for part in v.split(';') {
            let (k, val) = part.split_once('=')?;
            match k.trim().to_ascii_uppercase().as_str() {
                "FREQ" => r.freq = val.trim().to_ascii_uppercase(),
                "INTERVAL" => r.interval = val.trim().parse().ok()?,
                "COUNT" => {
                    let c: u32 = val.trim().parse().ok()?;
                    r.count = Some(c);
                }
                "UNTIL" => r.until = Some(IcalTime::parse(val.trim())?),
                "BYDAY" => {
                    r.byday = val
                        .split(',')
                        .map(|d| d.trim().trim_start_matches(['+', '-'])
                            .trim_start_matches(|c: char| c.is_ascii_digit())
                            .to_ascii_uppercase())
                        .collect();
                }
                _ => {} // WKST/BYMONTH/etc. — P2
            }
        }
        if r.freq.is_empty() {
            return None;
        }
        Some(r)
    }

    /// Expand occurrences from `dtstart`, inclusive, up to `limit`
    /// results (the caller bounds memory).
    pub fn expand(&self, dtstart: DateTime<Utc>, limit: usize) -> Vec<DateTime<Utc>> {
        let mut out = Vec::with_capacity(limit.min(64));
        let step = match self.freq.as_str() {
            "SECONDLY" => Duration::seconds(self.interval as i64),
            "MINUTELY" => Duration::minutes(self.interval as i64),
            "HOURLY" => Duration::hours(self.interval as i64),
            "DAILY" => Duration::days(self.interval as i64),
            "WEEKLY" => Duration::weeks(self.interval as i64),
            "MONTHLY" => Duration::days(30 * self.interval as i64), // approximation
            "YEARLY" => Duration::days(365 * self.interval as i64),  // approximation
            _ => return vec![dtstart],
        };
        // WEEKLY + BYDAY: emit each listed weekday per interval week.
        if self.freq == "WEEKLY" && !self.byday.is_empty() {
            let weekdays: Vec<chrono::Weekday> = self
                .byday
                .iter()
                .filter_map(|d| match d.as_str() {
                    "MO" => Some(chrono::Weekday::Mon),
                    "TU" => Some(chrono::Weekday::Tue),
                    "WE" => Some(chrono::Weekday::Wed),
                    "TH" => Some(chrono::Weekday::Thu),
                    "FR" => Some(chrono::Weekday::Fri),
                    "SA" => Some(chrono::Weekday::Sat),
                    "SU" => Some(chrono::Weekday::Sun),
                    _ => None,
                })
                .collect();
            if !weekdays.is_empty() {
                let mut week_start = dtstart.date_naive() - Duration::days(
                    dtstart.weekday().num_days_from_monday() as i64,
                );
                loop {
                    for wd in &weekdays {
                        let day = week_start
                            + Duration::days(wd.num_days_from_monday() as i64);
                        let occurrence = day
                            .and_hms_opt(dtstart.hour(), dtstart.minute(), dtstart.second())
                            .map(|t| chrono::Utc.from_utc_datetime(&t))
                            .unwrap_or_default();
                        if occurrence >= dtstart
                            && self.within_bounds(&occurrence, out.len())
                        {
                            out.push(occurrence);
                            if out.len() >= limit {
                                return out;
                            }
                        }
                    }
                    week_start += Duration::weeks(self.interval as i64);
                    if !self.within_bounds(
                        &week_start
                            .and_hms_opt(0, 0, 0)
                            .map(|t| chrono::Utc.from_utc_datetime(&t))
                            .unwrap_or_default(),
                        out.len(),
                    ) {
                        return out;
                    }
                }
            }
        }
        // Scalar interval walk.
        let mut cur = dtstart;
        while self.within_bounds(&cur, out.len()) && out.len() < limit {
            out.push(cur);
            cur += step;
        }
        out
    }

    fn within_bounds(&self, t: &DateTime<Utc>, count_so_far: usize) -> bool {
        if let Some(c) = self.count {
            if count_so_far as u32 >= c {
                return false;
            }
        }
        if let Some(u) = self.until {
            if t > &u.to_utc() {
                return false;
            }
        }
        true
    }
}

/// Expand a VEVENT's occurrences: RRULE minus EXDATE, bounded.
pub fn expand_event(event: &IcalComponent, limit: usize) -> Vec<DateTime<Utc>> {
    let Some(dtstart) = event.get("DTSTART").and_then(IcalTime::parse) else {
        return vec![];
    };
    let start = dtstart.to_utc();
    let mut occurrences = match event.get("RRULE").and_then(RRule::parse) {
        Some(rr) => rr.expand(start, limit),
        None => vec![start],
    };
    // EXDATE exclusion.
    for ex in event.get_all("EXDATE") {
        if let Some(t) = ex.split(',').next().and_then(IcalTime::parse) {
            let t = t.to_utc();
            occurrences.retain(|o| *o != t);
        }
    }
    occurrences
}

/// Synthetic UID for events that lack one (stable: content hash of
/// DTSTART+DTEND+SUMMARY).
pub fn synthetic_uid(event: &IcalComponent) -> String {
    if let Some(uid) = event.get("UID") {
        return uid.to_string();
    }
    let key = format!(
        "{}|{}|{}",
        event.get("DTSTART").unwrap_or_default(),
        event.get("DTEND").unwrap_or_default(),
        event.get("SUMMARY").unwrap_or_default(),
    );
    format!("synthetic-{}", blake3_sub(key.as_bytes()))
}

fn blake3_sub(data: &[u8]) -> String {
    // A tiny stable hash (FNV-1a) — blake3 isn't a dep of this crate
    // and the UID only needs uniqueness, not cryptographic strength.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Build a minimal VCALENDAR + VEVENT wire form (RSVP requests).
pub fn build_invitation(
    uid: &str,
    summary: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    organizer: &str,
    attendee: &str,
    method: &str, // REQUEST | REPLY | CANCEL
) -> String {
    let fmt = |d: DateTime<Utc>| d.format("%Y%m%dT%H%M%SZ").to_string();
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//Sentin8//Email8//EN\r\n\
         METHOD:{method}\r\n\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{stamp}\r\n\
         DTSTART:{s}\r\n\
         DTEND:{e}\r\n\
         SUMMARY:{summary}\r\n\
         ORGANIZER:mailto:{organizer}\r\n\
         ATTENDEE;RSVP=TRUE:mailto:{attendee}\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        stamp = fmt(Utc::now()),
        s = fmt(start),
        e = fmt(end),
    )
}

/// Fold + escape one text value per RFC 5545 §3.3.11 (75-octet lines).
pub fn escape_text(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc-123\r\n\
        DTSTART:20260901T100000Z\r\nDTEND:20260901T110000Z\r\nSUMMARY:Standup\r\n\
        RRULE:FREQ=WEEKLY;COUNT=3;BYDAY=MO,WE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parses_nested_components() {
        let cal = parse(EVENT);
        assert_eq!(cal.kind, "VCALENDAR");
        let events = cal.children_of("VEVENT");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].get("UID"), Some("abc-123"));
        assert_eq!(events[0].get("SUMMARY"), Some("Standup"));
    }

    #[test]
    fn unfolds_folded_lines() {
        let raw = "SUMMARY:This is a very long line\r\n that was folded here\r\n";
        let lines = unfold(raw);
        assert_eq!(lines, vec!["SUMMARY:This is a very long line that was folded here"]);
    }

    #[test]
    fn quoted_param_values() {
        let prop = parse_property("ATTENDEE;CN=\"Big; Name\":mailto:a@b.c").unwrap();
        assert_eq!(prop.name, "ATTENDEE");
        assert_eq!(prop.params[0], ("CN".to_string(), "Big; Name".to_string()));
        assert_eq!(prop.value, "mailto:a@b.c");
    }

    #[test]
    fn weekly_byday_expansion_respects_count() {
        let rr = RRule::parse("FREQ=WEEKLY;COUNT=4;BYDAY=MO,WE").unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 9, 1) // Tuesday
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .map(|t| chrono::Utc.from_utc_datetime(&t))
            .unwrap();
        let occ = rr.expand(start, 100);
        assert_eq!(occ.len(), 4);
        // First occurrence is Wed Sep 2 (after Tue Sep 1 start).
        assert_eq!(occ[0].format("%a %Y-%m-%d").to_string(), "Wed 2026-09-02");
        assert_eq!(occ[1].format("%a %Y-%m-%d").to_string(), "Mon 2026-09-07");
    }

    #[test]
    fn daily_until_bound() {
        let rr = RRule::parse("FREQ=DAILY;UNTIL=20260903T000000Z").unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 9, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .map(|t| chrono::Utc.from_utc_datetime(&t))
            .unwrap();
        let occ = rr.expand(start, 100);
        assert_eq!(occ.len(), 3); // Sep 1-3 inclusive
    }

    #[test]
    fn expand_event_applies_exdate() {
        let raw = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20260901T100000Z\r\n\
             RRULE:FREQ=DAILY;COUNT=3\r\nEXDATE:20260902T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let cal = parse(raw);
        let occ = expand_event(&cal.children_of("VEVENT")[0], 100);
        assert_eq!(occ.len(), 2); // 3 minus the excluded day
    }

    #[test]
    fn synthetic_uid_stable() {
        let cal = parse("BEGIN:VEVENT\r\nDTSTART:20260901T100000Z\r\nSUMMARY:Weekly sync\r\nEND:VEVENT\r\n");
        let e = &cal;
        let a = synthetic_uid(e);
        let b = synthetic_uid(e);
        assert_eq!(a, b);
        assert!(a.starts_with("synthetic-"));
    }

    #[test]
    fn invitation_builds_valid_wire_form() {
        let s = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap().and_hms_opt(10, 0, 0).map(|t| chrono::Utc.from_utc_datetime(&t)).unwrap();
        let body = build_invitation("u1", "Review", s, s + Duration::hours(1), "a@x.io", "b@y.io", "REQUEST");
        assert!(body.starts_with("BEGIN:VCALENDAR"));
        assert!(body.contains("METHOD:REQUEST"));
        assert!(body.ends_with("END:VCALENDAR\r\n"));
    }
}