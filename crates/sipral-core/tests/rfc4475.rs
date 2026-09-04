// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The RFC 4475 torture corpus, run against the message layer.
//!
//! `fixtures/rfc4475/manifest.toml` says what each of the 49 messages is
//! supposed to do. This reads it and holds the layer to it:
//!
//! - `parse` — the message is well formed and has to survive a round trip
//!   byte for byte.
//! - `reject` — either the parser refuses it, or it parses and
//!   [`RawMessage::validate`] refuses it. Both are the stack answering 400;
//!   which one happens depends on whether the fault is in the framing or in a
//!   field, and the RFC does not care.
//! - `semantic` — well formed, and what to do about it lives in a layer above
//!   this one.
//!
//! The manifest is read by hand rather than with a TOML crate. The format is
//! ours, three keys matter, and `sipral-core` has no dependencies on purpose.

// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "this is a test binary, not the library"
)]

use std::fs;
use std::path::{Path, PathBuf};

use sipral_core::msg::{ParseMode, ParseScratch, RawMessage, parse};

struct Entry {
    name: String,
    section: String,
    file: String,
    outcome: String,
}

fn fixtures() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sipral-core
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/rfc4475")
}

/// Read the `[[message]]` blocks. Values are quoted strings on their own line,
/// which is all this manifest ever holds.
fn manifest() -> Vec<Entry> {
    let text = fs::read_to_string(fixtures().join("manifest.toml")).expect("the manifest");
    let mut entries = Vec::new();
    let mut current: Option<(String, String, String, String)> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[message]]" {
            if let Some((name, section, file, outcome)) = current.take() {
                entries.push(Entry {
                    name,
                    section,
                    file,
                    outcome,
                });
            }
            current = Some((String::new(), String::new(), String::new(), String::new()));
            continue;
        }
        let Some(slot) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "name" => slot.0 = value,
            "section" => slot.1 = value,
            "file" => slot.2 = value,
            "outcome" => slot.3 = value,
            _ => {}
        }
    }
    if let Some((name, section, file, outcome)) = current {
        entries.push(Entry {
            name,
            section,
            file,
            outcome,
        });
    }
    entries
}

/// What the stack would do with this message.
enum Verdict {
    Accepted,
    Refused(String),
}

fn judge(bytes: &[u8]) -> Verdict {
    let mut scratch = ParseScratch::new();
    match parse(bytes, &mut scratch, ParseMode::Strict) {
        Err(e) => Verdict::Refused(format!("parse: {e}")),
        Ok(message) => match message.validate() {
            Err(e) => Verdict::Refused(format!("validate: {e}")),
            Ok(()) => Verdict::Accepted,
        },
    }
}

fn round_trips(bytes: &[u8]) -> bool {
    let mut scratch = ParseScratch::new();
    let Ok(message) = parse(bytes, &mut scratch, ParseMode::Strict) else {
        return false;
    };
    let owned = message.to_owned();
    // 3.1.1.8 dblreq puts two requests in one datagram; only the first is
    // this message, and the rest is the next one's problem
    owned.as_raw().as_bytes() == bytes.get(..message.len()).unwrap_or_default()
}

#[test]
fn the_corpus_behaves_as_the_manifest_says() {
    let entries = manifest();
    assert_eq!(entries.len(), 49, "the manifest lost a message");

    let mut failures: Vec<String> = Vec::new();
    for entry in &entries {
        let path = fixtures().join(&entry.file);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", entry.file));
        let where_ = format!("{} (§{}, {})", entry.name, entry.section, entry.outcome);

        match (entry.outcome.as_str(), judge(&bytes)) {
            ("parse" | "semantic", Verdict::Refused(why)) => {
                failures.push(format!("{where_}: expected acceptance, got {why}"));
            }
            ("reject", Verdict::Accepted) => {
                failures.push(format!("{where_}: expected a rejection, got none"));
            }
            ("parse", Verdict::Accepted) if !round_trips(&bytes) => {
                failures.push(format!("{where_}: does not round trip"));
            }
            _ => {}
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} messages behaved differently:\n{}",
        failures.len(),
        entries.len(),
        failures.join("\n")
    );
}

#[test]
fn the_groups_are_the_sizes_the_stage_gate_expects() {
    let entries = manifest();
    let count = |outcome: &str| entries.iter().filter(|e| e.outcome == outcome).count();
    assert_eq!(count("parse"), 13);
    assert_eq!(count("reject"), 22);
    assert_eq!(count("semantic"), 14);
}

#[test]
fn nothing_in_the_corpus_makes_the_parser_panic_when_truncated() {
    // every prefix of every message, which is what a stream hands over
    for entry in manifest() {
        let bytes = fs::read(fixtures().join(&entry.file)).expect("a fixture");
        for cut in 0..bytes.len() {
            let mut scratch = ParseScratch::new();
            let head = bytes.get(..cut).unwrap_or_default();
            if let Ok(message) = parse(head, &mut scratch, ParseMode::Strict) {
                let _ = message.validate();
                let _ = walk(&message);
            }
        }
    }
}

/// Touch every accessor, so a panic anywhere has somewhere to show up.
fn walk(m: &RawMessage<'_>) -> usize {
    let mut seen = 0;
    seen += m.via().count();
    seen += m.route().count();
    seen += m.record_route().count();
    seen += m.allow().count();
    seen += m.supported().count();
    seen += m.require().count();
    seen += m.www_authenticate().count();
    seen += m.authorization().count();
    let _ = m.from();
    let _ = m.to();
    let _ = m.contact();
    let _ = m.cseq();
    let _ = m.call_id();
    let _ = m.date();
    let _ = m.expires();
    let _ = m.max_forwards();
    let _ = m.content_type();
    let _ = m.transaction_lookup_method();
    seen
}
