// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Narrow tests over the parsing and rendering this tool does not get to
//! prove against a real `cargo tree` in `scripts/check.sh` alone: the SPDX
//! rewrite, the `THIRD-PARTY-LICENSES.txt` heading parser the `--notices`
//! gate depends on, JSON string escaping, and the date arithmetic behind the
//! one timestamp field. Each was run against a version of the function that
//! did not have the fix yet, watched to fail, then restored.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;

use super::{civil_from_days, iso8601_now, json_escape, normalise_spdx, notices_components};

#[test]
fn normalise_spdx_rewrites_the_slash_join_rust_crates_write() {
    // Cargo's own convention, seen on the majority of crates.io: not a legal
    // SPDX expression, which joins alternatives with the keyword `OR`.
    assert_eq!(normalise_spdx("MIT/Apache-2.0"), "MIT OR Apache-2.0");
    // Already legal SPDX: passed through unchanged, not re-joined into
    // "Apache-2.0 OR MIT" and silently reordered.
    assert_eq!(normalise_spdx("Apache-2.0 OR MIT"), "Apache-2.0 OR MIT");
    // A single licence: no operator to insert.
    assert_eq!(normalise_spdx("BSD-3-Clause"), "BSD-3-Clause");
    // A `license-file` pointer, [`read_license_expression`]'s `see <file>`
    // form: left as free text, since there is no SPDX identifier to write
    // for a licence this tool never named.
    assert_eq!(normalise_spdx("see LICENSE-MIT"), "see LICENSE-MIT");
}

#[test]
fn notices_components_reads_sipral_license_gens_heading_shape() {
    // `sipral-license-gen`'s `render_entry`: a heading of "{name} {version}
    // -- {license}" between two rules of dashes, and nothing else in the
    // file takes that exact shape -- the prose around it must not be read as
    // more crates.
    let text = "\
Sipral - third-party licences
==============================

This lists every one of the 2 third-party components...

-------------------
opus 0.4.0 -- MIT/Apache-2.0
-------------------

[LICENSE-MIT]

Some licence text, with a line that could look like a heading -- but is not.

----------------------------
opusic-sys 0.7.5 -- BSD-3-Clause
----------------------------

[LICENSE]

More text.
";
    let got = notices_components(text);
    let want: std::collections::BTreeSet<(String, String)> = [
        ("opus".to_string(), "0.4.0".to_string()),
        ("opusic-sys".to_string(), "0.7.5".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

#[test]
fn notices_components_ignores_a_prose_line_with_the_same_separator() {
    // "with a line that could look like a heading -- but is not" above
    // already covers this once end to end; this isolates the one thing that
    // makes it safe: the text before " -- " has to end in "<name> <version>",
    // a version starting with a digit, or it is not counted.
    let text = "a line that could look like a heading -- but is not\n";
    assert!(notices_components(text).is_empty());
}

#[test]
fn json_escape_covers_what_a_crate_or_licence_name_can_hold() {
    assert_eq!(json_escape("plain"), "plain");
    assert_eq!(json_escape("a\"b"), "a\\\"b");
    assert_eq!(json_escape("a\\b"), "a\\\\b");
    assert_eq!(json_escape("a\nb"), "a\\nb");
    // A control character below the printable range, escaped numerically
    // rather than passed through raw into a JSON string.
    assert_eq!(json_escape("a\u{1}b"), "a\\u0001b");
}

#[test]
fn civil_from_days_matches_known_dates() {
    // The Unix epoch itself.
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    // A leap day, the case every hand-rolled calendar gets wrong first.
    assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    // A date this document was plausibly written on, cross-checked against
    // Python's own `datetime.date(2024, 9, 27) - datetime.date(1970, 1, 1)`
    // independently of this function.
    assert_eq!(civil_from_days(19_993), (2024, 9, 27));
}

#[test]
fn iso8601_now_is_well_formed() {
    let now = iso8601_now();
    assert_eq!(now.len(), 20, "{now}");
    assert!(now.ends_with('Z'), "{now}");
    assert_eq!(&now[4..5], "-", "{now}");
    assert_eq!(&now[7..8], "-", "{now}");
    assert_eq!(&now[10..11], "T", "{now}");
}

#[test]
fn read_opus_package_version_reads_libopus_own_version_line() {
    let dir = std::env::temp_dir().join(format!(
        "sipral-sbom-gen-test-{}-{}",
        std::process::id(),
        line!()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("package_version");
    fs::write(&path, "PACKAGE_VERSION=\"1.6.1\"\n").expect("write fixture");

    let version = super::read_opus_package_version(&path).expect("parse");
    assert_eq!(version, "1.6.1");

    fs::remove_dir_all(&dir).ok();
}
