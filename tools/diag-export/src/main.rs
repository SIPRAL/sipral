// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `diag-export`: turn a D2 replay recording (`docs/18-replay.md`) into a
//! pcapng file a NOC can open in Wireshark, optionally redacting the
//! personal data out of it first (`docs/14-diagnostics.md`).
//!
//! ```text
//! diag-export <input.sipralrec> <output.pcapng>
//! diag-export --redact --key-file <path> <input.sipralrec> <output.pcapng>
//! diag-export --redact --delete <input.sipralrec> <output.pcapng>
//! ```
//!
//! `--key-file` reads the organisation's HMAC key as raw bytes rather than
//! taking it on the command line, which a shell keeps in its history and a
//! process list can show to anyone else on the machine.

// tests say what they mean; the no-panic discipline is for the binary
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

use std::env;
use std::fs;
use std::process::ExitCode;

use sipral_core::replay::Recording;
use sipral_diag::{Mode, Redactor, export};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("diag-export: {message}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    input: String,
    output: String,
    redactor: Option<Redactor>,
}

fn parse_args(argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut redact = false;
    let mut delete = false;
    let mut key_file: Option<String> = None;
    let mut positional = Vec::new();

    let mut argv = argv;
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--redact" => redact = true,
            "--delete" => delete = true,
            "--key-file" => key_file = Some(argv.next().ok_or("--key-file needs a path")?),
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other => positional.push(other.to_string()),
        }
    }

    let [input, output] = <[String; 2]>::try_from(positional)
        .map_err(|_| "usage: diag-export [--redact --key-file <path> | --redact --delete] <input.sipralrec> <output.pcapng>".to_string())?;

    let redactor = if redact {
        if delete {
            Some(Redactor::new(Mode::Delete))
        } else {
            let path = key_file.ok_or("--redact needs --key-file <path> or --delete")?;
            let key = fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
            Some(Redactor::new(Mode::Hash(key)))
        }
    } else if delete || key_file.is_some() {
        return Err("--delete and --key-file only apply with --redact".to_string());
    } else {
        None
    };

    Ok(Args {
        input,
        output,
        redactor,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args().skip(1))?;

    let text =
        fs::read_to_string(&args.input).map_err(|e| format!("reading {}: {e}", args.input))?;
    let recording = Recording::parse(&text).map_err(|e| format!("parsing {}: {e}", args.input))?;

    let pcapng =
        export(&recording, args.redactor).map_err(|e| format!("redacting {}: {e}", args.input))?;

    fs::write(&args.output, pcapng).map_err(|e| format!("writing {}: {e}", args.output))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn no_flags_means_no_redaction() {
        let args = parse_args(["in.sipralrec".to_string(), "out.pcapng".to_string()].into_iter())
            .expect("two positional arguments parse");
        assert_eq!(args.input, "in.sipralrec");
        assert_eq!(args.output, "out.pcapng");
        assert!(args.redactor.is_none());
    }

    #[test]
    fn redact_without_a_mode_is_an_error() {
        let result = parse_args(
            [
                "--redact".to_string(),
                "in.sipralrec".to_string(),
                "out.pcapng".to_string(),
            ]
            .into_iter(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn redact_delete_needs_no_key() {
        let args = parse_args(
            [
                "--redact".to_string(),
                "--delete".to_string(),
                "in.sipralrec".to_string(),
                "out.pcapng".to_string(),
            ]
            .into_iter(),
        )
        .expect("--redact --delete parses");
        assert!(args.redactor.is_some());
    }

    #[test]
    fn delete_without_redact_is_an_error() {
        let result = parse_args(
            [
                "--delete".to_string(),
                "in.sipralrec".to_string(),
                "out.pcapng".to_string(),
            ]
            .into_iter(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_wrong_number_of_positional_arguments_is_an_error() {
        assert!(parse_args(["only-one".to_string()].into_iter()).is_err());
        assert!(
            parse_args(["one".to_string(), "two".to_string(), "three".to_string()].into_iter())
                .is_err()
        );
    }
}
