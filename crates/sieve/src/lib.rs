// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Email8 Sieve — RFC 5228 grammar (untrusted user scripts + trusted
//! stage scripts share one compiler), interpreter with the core
//! extension set: fileinto, redirect, reject, keep, stop, discard,
//! vacation, comparator-i;ascii-numeric (subset), relational (eq/ne via
//! numeric), plus header/address/body/test lists.
//!
//! Actions are *collected* — the caller (Store ingest / Mta stage) applies
//! them against its data model. The interpreter never performs I/O.

pub mod compiler;
pub mod interpreter;

pub use compiler::{compile, CompilerError, Script};
pub use interpreter::{run, Action, InterpreterError, Mail};

/// Advertised SIEVE capability string for ManageSieve.
pub const SIEVE_EXTENSIONS: &[&str] = &[
    "fileinto",
    "redirect",
    "reject",
    "keep",
    "stop",
    "discard",
    "vacation",
    "envelope",
    "comparator-i;ascii-casemap",
    "comparator-i;ascii-numeric",
    "body",
    "imap4flags",
    "variables",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn mail() -> Mail {
        Mail {
            from: "alice@example.com".into(),
            to: vec!["bob@example.net".into()],
            headers: vec![
                ("from".into(), "alice@example.com".into()),
                ("to".into(), "bob@example.net".into()),
                ("subject".into(), "[list] Hello".into()),
            ],
            body: b"Buy widgets now!".to_vec(),
            size: 512,
        }
    }

    #[test]
    fn fileinto_subject_match() {
        let script = compile(
            r#"require ["fileinto"];
if header :contains "subject" "[list]" {
    fileinto "Lists";
    stop;
}
keep;"#,
        )
        .unwrap();
        let actions = run(&script, &mail()).unwrap();
        assert_eq!(
            actions,
            vec![Action::FileInto("Lists".into()), Action::Stop]
        );
    }

    #[test]
    fn reject_spam_keyword() {
        let script = compile(
            r#"if body :contains "widgets" {
    reject "No spam please";
}"#,
        )
        .unwrap();
        let actions = run(&script, &mail()).unwrap();
        assert_eq!(
            actions,
            vec![Action::Reject("No spam please".into()), Action::Stop]
        );
    }

    #[test]
    fn redirect_else_keep() {
        let script = compile(
            r#"if header :is "from" "ceo@example.com" {
    redirect "assistant@example.net";
} else {
    keep;
}"#,
        )
        .unwrap();
        let actions = run(&script, &mail()).unwrap();
        assert_eq!(actions, vec![Action::Keep]);
    }

    #[test]
    fn size_test_numeric() {
        let script = compile(
            r#"if size :over 100 {
    discard;
    stop;
}"#,
        )
        .unwrap();
        let actions = run(&script, &mail()).unwrap();
        assert_eq!(actions, vec![Action::Discard, Action::Stop]);
    }

    #[test]
    fn unknown_require_fails() {
        assert!(compile("require \"frobnicate\";").is_err());
    }
}
