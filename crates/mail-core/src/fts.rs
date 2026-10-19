// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! FTS support (story 2.6) - ingest-side language detection for
//! tsvector configuration and SearchSnippet extraction for JMAP
//! `Email/query` highlight results.
//!
//! Language detection is script/stopword based (no external model): a
//! stopword-frequency probe over a fixed language set covers the
//! realistic operator base; unknown corpora default to `simple`.

/// Languages with Postgres tsvector configurations we support.
pub const LANGS: &[(&str, &[&str])] = &[
    (
        "english",
        &[
            "the", "and", "is", "of", "to", "in", "that", "it", "for", "with",
        ],
    ),
    (
        "german",
        &[
            "der", "die", "das", "und", "ist", "nicht", "mit", "ein", "eine", "auf",
        ],
    ),
    (
        "french",
        &[
            "le", "la", "les", "et", "est", "un", "une", "pour", "avec", "que",
        ],
    ),
    (
        "spanish",
        &[
            "el", "la", "los", "las", "es", "un", "una", "para", "con", "que",
        ],
    ),
    (
        "italian",
        &[
            "il", "la", "gli", "e", "è", "un", "una", "per", "con", "che",
        ],
    ),
    (
        "dutch",
        &[
            "de", "het", "een", "en", "is", "van", "niet", "met", "voor", "dat",
        ],
    ),
    (
        "portuguese",
        &["o", "a", "os", "as", "é", "um", "uma", "para", "com", "que"],
    ),
    (
        "russian",
        &["и", "в", "не", "на", "что", "это", "как", "по", "из", "за"],
    ),
];

/// Detect the Postgres tsvector config for a text corpus. Falls back to
/// `simple` for CJK/script-mixed or short corpora.
pub fn detect_tsvector_lang(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    // Non-Latin scripts get simple (the text search configs for them are
    // optional extensions).
    if lower.chars().any(|c| matches!(c as u32, 0x0400..=0x04FF | 0x4E00..=0x9FFF | 0x3040..=0x30FF | 0xAC00..=0xD7AF)) {
        return "simple";
    }
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|w| w.len() > 1)
        .collect();
    if words.len() < 8 {
        return "simple";
    }
    let mut best: (&str, usize) = ("simple", 2); // require ≥3 stopword hits
    for (lang, stops) in LANGS {
        let hits = words.iter().filter(|w| stops.contains(w)).count();
        if hits > best.1 {
            best = (lang, hits);
        }
    }
    best.0
}

/// A SearchSnippet (RFC 8620 §5): the matched text with `…` around the
/// best match window. JMAP clients render the subject/body snippet.
pub struct Snippet {
    /// Snippet for the `preview` field (no HTML).
    pub preview: String,
}

/// Build a snippet from a body text around the first occurrence of any
/// query term (case-insensitive). Falls back to the head of the text.
pub fn snippet(body: &str, query: &str, max_chars: usize) -> Snippet {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .filter(|t| t.len() >= 2)
        .collect();
    let flat: String = body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut hit: Option<usize> = None;
    for term in &terms {
        if let Some(pos) = lower_find(&flat, term) {
            hit = Some(pos);
            break;
        }
    }
    let Some(pos) = hit else {
        // No match - head of the text.
        return Snippet {
            preview: truncate_chars(&flat, max_chars),
        };
    };
    // Center the window on the match while keeping the full matched term
    // inside the window.
    let matched_len = flat[pos..].find(' ').unwrap_or(flat.len() - pos);
    let pre = max_chars.saturating_sub(matched_len) / 2;
    let start = pos.saturating_sub(pre);
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    let slice = &flat[start..];
    out.push_str(&truncate_chars(slice, max_chars));
    if start + out.chars().count() - usize::from(start > 0) < flat.chars().count() {
        out.push('…');
    }
    Snippet { preview: out }
}

fn lower_find(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.to_lowercase();
    hay.find(needle)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Language detection ────────────────────────────────────────────

    #[test]
    fn english_detected() {
        let text = "The quick brown fox is one of the animals that it is known for in the field";
        assert_eq!(detect_tsvector_lang(text), "english");
    }

    #[test]
    fn german_detected() {
        let text = "Der Hund ist nicht in dem Haus und das ist gut mit einer eine der";
        assert_eq!(detect_tsvector_lang(text), "german");
    }

    #[test]
    fn short_corpus_falls_back_to_simple() {
        assert_eq!(detect_tsvector_lang("hello there"), "simple");
    }

    #[test]
    fn cyrillic_script_defaults_to_simple() {
        let text = "Это тест на русском языке для проверки простой конфигурации";
        assert_eq!(detect_tsvector_lang(text), "simple");
    }

    #[test]
    fn cjk_defaults_to_simple() {
        assert_eq!(
            detect_tsvector_lang("これは日本語のテキストです。テストです。"),
            "simple"
        );
    }

    #[test]
    fn every_lang_has_ten_stopwords() {
        for (lang, stops) in LANGS {
            assert_eq!(stops.len(), 10, "{lang} stopword count drifted");
        }
    }

    // ── Snippets ──────────────────────────────────────────────────────

    #[test]
    fn snippet_centers_on_first_term_match() {
        let body = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. The contract value is due next week.";
        let s = snippet(body, "contract", 40);
        assert!(s.preview.contains("contract"), "got: {}", s.preview);
        assert!(s.preview.starts_with('…') || s.preview.len() < 40);
    }

    #[test]
    fn snippet_case_insensitive_match() {
        let s = snippet("The CONTRACT was signed", "contract", 50);
        assert!(s.preview.contains("CONTRACT"));
    }

    #[test]
    fn snippet_no_match_returns_head() {
        let body = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let s = snippet(body, "missing", 20);
        assert_eq!(s.preview, "alpha beta gamma del");
    }

    #[test]
    fn snippet_empty_query_returns_head() {
        let s = snippet("hello world this is a body", "   ", 10);
        assert_eq!(s.preview, "hello worl");
    }

    #[test]
    fn snippet_multiline_body_flattened() {
        let body = "line one\n\nline two\nline three";
        let s = snippet(body, "two", 30);
        assert!(s.preview.contains("line two"));
        assert!(!s.preview.contains('\n'));
    }

    #[test]
    fn snippet_truncates_on_char_boundaries() {
        // Multi-byte characters must not panic mid-codepoint.
        let body = "café naïve résumé über straße café naïve résumé über straße";
        let s = snippet(body, "straße", 12);
        assert!(s.preview.chars().count() <= 14);
    }

    #[test]
    fn snippet_single_term_short_body_no_ellipsis() {
        let s = snippet("short", "short", 50);
        assert_eq!(s.preview, "short");
    }
}
