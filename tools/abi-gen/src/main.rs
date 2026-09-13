// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Print the C header and the three bindings from what `sipral-ffi` declares.
//!
//! `cargo run -p sipral-abi-gen` writes them; `--check` prints them into
//! memory and says which committed file no longer matches, which is what
//! `scripts/check.sh` runs. Nothing here reads Rust source: the surface is a
//! `const` the compiler built out of the declarations themselves, so a `cfg`
//! that changed what is declared changes what is printed.

mod c;
mod csharp;
mod kotlin;
mod model;
mod names;
mod sizes;
mod swift;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sipral_ffi::abi::SURFACE;

use model::Refused;

/// Where the repository is, whatever directory the tool was started from.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Everything printed from the surface, and where it belongs.
fn outputs() -> Result<Vec<(PathBuf, String)>, Refused> {
    let here = root();
    Ok(vec![
        (
            here.join("bindings/c/include/sipral.h"),
            c::header(&SURFACE)?,
        ),
        (
            here.join("bindings/swift/Sources/Sipral/SipralAbi.swift"),
            swift::binding(&SURFACE)?,
        ),
        (
            here.join("bindings/dotnet/Sipral/SipralAbi.cs"),
            csharp::binding(&SURFACE)?,
        ),
        (
            here.join("bindings/kotlin/sipral/src/main/kotlin/org/sipral/SipralAbi.kt"),
            kotlin::binding(&SURFACE)?,
        ),
        (
            here.join("bindings/kotlin/sipral/src/main/jni/sipral_jni.c"),
            kotlin::shim(&SURFACE)?,
        ),
        (
            here.join("bindings/c/abi-sizes.txt"),
            sizes::rendered(&SURFACE),
        ),
    ])
}

fn shorten(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn write(files: &[(PathBuf, String)]) -> Result<(), String> {
    for (path, content) in files {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|why| format!("{}: {why}", shorten(parent)))?;
        }
        std::fs::write(path, content).map_err(|why| format!("{}: {why}", shorten(path)))?;
        println!("wrote {}", shorten(path));
    }
    Ok(())
}

fn check(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut stale = Vec::new();
    for (path, content) in files {
        match std::fs::read_to_string(path) {
            Ok(committed) if committed == *content => {}
            Ok(_) => stale.push(format!(
                "{} is not what the declarations produce",
                shorten(path)
            )),
            Err(why) => stale.push(format!("{}: {why}", shorten(path))),
        }
    }
    stale
}

fn main() -> ExitCode {
    let checking = std::env::args().any(|argument| argument == "--check");
    let files = match outputs() {
        Ok(files) => files,
        Err(why) => {
            eprintln!("the surface cannot be printed: {why}");
            return ExitCode::FAILURE;
        }
    };
    if !checking {
        return match write(&files) {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("could not write: {why}");
                ExitCode::FAILURE
            }
        };
    }
    let stale = check(&files);
    if stale.is_empty() {
        println!("the header and the bindings match the declarations");
        return ExitCode::SUCCESS;
    }
    for line in &stale {
        eprintln!("{line}");
    }
    eprintln!("run: cargo run -p sipral-abi-gen");
    ExitCode::FAILURE
}
