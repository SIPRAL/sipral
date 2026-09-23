// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Regenerate `THIRD-PARTY-LICENSES.txt`.
//!
//! For every normal dependency of the crates Sipral ships a binary of
//! (`sipral`, `sipral-ffi`), across every target the project builds for, this
//! prints the crate's name, version, licence expression and the full licence
//! text(s) as that crate's own source ships them — the file a licensee is
//! told to ship alongside a Sipral binary.
//!
//! `cargo run -p sipral-license-gen` writes the file at the workspace root.
//! `cargo run -p sipral-license-gen -- --check` compares it against what is
//! committed and exits non-zero on a difference, without touching it — that
//! is what `scripts/check.sh` runs.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The crates whose normal dependency graph this tool reproduces licences
/// for. The bindings (Swift, .NET, Kotlin, Python, the C header) all call
/// into `sipral-ffi` and bring no dependency of their own into a shipped
/// binary.
const SHIPPED_CRATES: &[&str] = &["sipral", "sipral-ffi"];

/// The generated file's path, relative to the workspace root.
const OUTPUT_FILE: &str = "THIRD-PARTY-LICENSES.txt";

/// Filenames, matched by prefix and case-insensitively, that carry a
/// component's own licence text at the root of its source tree.
const LICENCE_FILE_PREFIXES: &[&str] = &["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"];

/// A licence-bearing file found at a dependency's root: its name and content.
struct LicenceFile {
    name: String,
    content: String,
}

fn main() -> ExitCode {
    let check_only = env::args().nth(1).as_deref() == Some("--check");
    match run(check_only) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("{OUTPUT_FILE} is stale; run `cargo run -p sipral-license-gen` to update it");
            ExitCode::FAILURE
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(check_only: bool) -> Result<bool, String> {
    let root = workspace_root()?;
    let members = workspace_member_names(&root)?;
    let deps = shipped_dependencies(&root, &members)?;
    let registry_roots = registry_src_roots()?;

    let mut rendered = String::new();
    render_header(&mut rendered, deps.len());
    for (name, version) in &deps {
        let dir = locate_crate_dir(&registry_roots, name, version).ok_or_else(|| {
            format!(
                "{name} {version} is not in a cached registry checkout; run `cargo fetch` first"
            )
        })?;
        let license = read_license_expression(&dir).ok_or_else(|| {
            format!("{name} {version}: no `license` or `license-file` field in its Cargo.toml")
        })?;
        let files = licence_files(&dir)
            .map_err(|e| format!("{name} {version}: reading its licence files: {e}"))?;
        if files.is_empty() {
            return Err(format!(
                "{name} {version}: declares `{license}` but ships no licence file at its root"
            ));
        }
        render_entry(&mut rendered, name, version, &license, &files);
    }

    if check_only {
        let committed = fs::read_to_string(root.join(OUTPUT_FILE)).unwrap_or_default();
        return Ok(committed == rendered);
    }

    fs::write(root.join(OUTPUT_FILE), rendered)
        .map_err(|e| format!("writing {OUTPUT_FILE}: {e}"))?;
    Ok(true)
}

/// Finds the workspace root by asking Cargo, rather than assuming the
/// current directory, so the tool works from anywhere inside the tree.
fn workspace_root() -> Result<PathBuf, String> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .map_err(|e| format!("running `cargo locate-project`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let manifest = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Path::new(&manifest)
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{manifest} has no parent directory"))
}

/// Every package name declared under a workspace member directory, read from
/// `[workspace] members` in the root manifest rather than hard-coded, so a
/// new crate under `crates/` is picked up without changing this tool. These
/// are excluded from the generated file: they are Sipral's own code, under
/// `LICENSE`, not a third-party dependency.
fn workspace_member_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("reading Cargo.toml: {e}"))?;
    let patterns = parse_members_array(&manifest).ok_or_else(|| {
        "Cargo.toml has no single-line `members = [...]` under [workspace]".to_string()
    })?;

    let mut names = BTreeSet::new();
    for pattern in patterns {
        for dir in expand_member_pattern(root, &pattern)? {
            if let Some(name) = read_package_name(&dir.join("Cargo.toml"))? {
                names.insert(name);
            }
        }
    }
    Ok(names)
}

/// Pulls the array literal out of a `members = [...]` line. The manifest
/// writes this on one line today; a tool that assumed otherwise would fail
/// silently instead of loudly, so this returns `None` rather than guessing
/// when it cannot find that shape.
fn parse_members_array(manifest: &str) -> Option<Vec<String>> {
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("members"))?;
    let open = line.find('[')?;
    let close = line.rfind(']')?;
    let inner = &line[open + 1..close];
    Some(
        inner
            .split(',')
            .map(|item| item.trim().trim_matches('"').to_string())
            .filter(|item| !item.is_empty())
            .collect(),
    )
}

/// `crates/*` becomes every subdirectory that has a `Cargo.toml`; anything
/// without a trailing `*` is a single member directory.
fn expand_member_pattern(root: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let base = root.join(prefix);
        let entries =
            fs::read_dir(&base).map_err(|e| format!("reading {}: {e}", base.display()))?;
        let mut dirs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("reading {}: {e}", base.display()))?;
            let path = entry.path();
            if path.is_dir() && path.join("Cargo.toml").is_file() {
                dirs.push(path);
            }
        }
        Ok(dirs)
    } else {
        Ok(vec![root.join(pattern)])
    }
}

/// The literal `name = "..."` under `[package]`. Every crate in this
/// workspace, and every crate on crates.io, declares this on its own line.
fn read_package_name(manifest_path: &Path) -> Result<Option<String>, String> {
    let manifest = fs::read_to_string(manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    Ok(field_value(&manifest, "name"))
}

/// The value of a top-level-quoted `key = "value"` line, taking the first
/// match. `Cargo.toml` files in this tree and in the registry write these
/// fields on one line, so this is a line scan, not a TOML parser.
fn field_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(value) = rest.strip_prefix('"')
                    && let Some(end) = value.find('"')
                {
                    return Some(value[..end].to_string());
                }
            }
        }
    }
    None
}

/// Runs `cargo tree` scoped to the shipped crates' normal dependency edges,
/// across every target, and returns the external (non-workspace) crates it
/// names, deduplicated and sorted. Relying on `cargo tree`'s own edge-kind
/// and per-target filtering, rather than reimplementing feature unification
/// here, is what keeps this tool small.
fn shipped_dependencies(
    root: &Path,
    members: &BTreeSet<String>,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut args = vec![
        "tree", "-e", "normal", "--prefix", "none", "--target", "all",
    ];
    for krate in SHIPPED_CRATES {
        args.push("-p");
        args.push(krate);
    }

    let mut offline_args = args.clone();
    offline_args.push("--offline");
    let mut output = Command::new("cargo")
        .current_dir(root)
        .args(&offline_args)
        .output()
        .map_err(|e| format!("running cargo tree: {e}"))?;
    if !output.status.success() {
        // The offline cache may be missing an entry cargo would otherwise
        // fetch; retry once online before giving up.
        output = Command::new("cargo")
            .current_dir(root)
            .args(&args)
            .output()
            .map_err(|e| format!("running cargo tree: {e}"))?;
    }
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut deps = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut tokens = line.split_whitespace();
        let Some(name) = tokens.next() else { continue };
        let Some(version_token) = tokens.next() else {
            continue;
        };
        let Some(version) = version_token.strip_prefix('v') else {
            continue;
        };
        if members.contains(name) {
            continue;
        }
        deps.insert((name.to_string(), version.to_string()));
    }
    Ok(deps)
}

/// Every `registry/src/<index>` directory under `$CARGO_HOME`, each of which
/// holds one `<name>-<version>` checkout per cached crate. More than one can
/// exist if the workspace has ever pointed at more than one registry.
fn registry_src_roots() -> Result<Vec<PathBuf>, String> {
    let cargo_home = env::var("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|_| env::var("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .map_err(|_| "neither CARGO_HOME nor HOME is set".to_string())?;
    let src = cargo_home.join("registry").join("src");
    let entries = fs::read_dir(&src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    let mut roots = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", src.display()))?;
        if entry.path().is_dir() {
            roots.push(entry.path());
        }
    }
    Ok(roots)
}

fn locate_crate_dir(roots: &[PathBuf], name: &str, version: &str) -> Option<PathBuf> {
    for root in roots {
        let candidate = root.join(format!("{name}-{version}"));
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// The crate's own declared licence: `license = "..."` verbatim, or, for the
/// handful of crates that point at a file instead, `see <that file>`.
fn read_license_expression(crate_dir: &Path) -> Option<String> {
    let manifest = fs::read_to_string(crate_dir.join("Cargo.toml")).ok()?;
    if let Some(license) = field_value(&manifest, "license") {
        return Some(license);
    }
    field_value(&manifest, "license-file").map(|file| format!("see {file}"))
}

/// The licence-bearing files at a dependency's own root, sorted by name. A
/// bare `LICENSE`/`LICENCE` that is too short to be more than a pointer (for
/// example a one-line SPDX expression) is left out when a fuller file is
/// also present, since that fuller file is what actually carries the text.
fn licence_files(crate_dir: &Path) -> Result<Vec<LicenceFile>, String> {
    let entries =
        fs::read_dir(crate_dir).map_err(|e| format!("reading {}: {e}", crate_dir.display()))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", crate_dir.display()))?;
        if !entry.path().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let upper = name.to_uppercase();
        if LICENCE_FILE_PREFIXES.iter().any(|p| upper.starts_with(p)) {
            names.push(name);
        }
    }
    names.sort();

    let mut files = Vec::new();
    for name in &names {
        let content =
            fs::read_to_string(crate_dir.join(name)).map_err(|e| format!("reading {name}: {e}"))?;
        let is_bare = name.eq_ignore_ascii_case("LICENSE") || name.eq_ignore_ascii_case("LICENCE");
        let is_pointer_stub = is_bare && content.trim().len() < 200 && names.len() > 1;
        if is_pointer_stub {
            continue;
        }
        files.push(LicenceFile {
            name: name.clone(),
            content,
        });
    }
    Ok(files)
}

fn render_header(out: &mut String, component_count: usize) {
    out.push_str(
        "Sipral - third-party licences\n\
         ==============================\n\
         \n\
         Ship this file, or an equivalent notice screen, with any binary that\n\
         contains Sipral: `LICENSE-COMMERCIAL.md` and `LICENSING.md` require it,\n\
         because the licences below require it themselves.\n\
         \n",
    );
    let _ = write!(
        out,
        "This lists every one of the {component_count} third-party components in \
         the normal (non-dev, non-build) dependency graph of the crates Sipral \
         ships a binary of -- `sipral` and `sipral-ffi` -- across every target the \
         project builds for: macOS, iOS, Windows and Linux. For each one: its name, \
         version, licence expression, and the full licence text(s) exactly as that \
         component's own source ships them.\n\
         \n\
         This file is generated. Do not edit it by hand: run\n\
         `cargo run -p sipral-license-gen` to regenerate it after any change to\n\
         `Cargo.lock`, and `cargo run -p sipral-license-gen -- --check`, which\n\
         `scripts/check.sh` runs, to check it is still current.\n\
         \n"
    );
}

fn render_entry(out: &mut String, name: &str, version: &str, license: &str, files: &[LicenceFile]) {
    let heading = format!("{name} {version} -- {license}");
    out.push_str(&"-".repeat(heading.len()));
    out.push('\n');
    out.push_str(&heading);
    out.push('\n');
    out.push_str(&"-".repeat(heading.len()));
    out.push_str("\n\n");
    for file in files {
        let _ = writeln!(out, "[{}]\n", file.name);
        out.push_str(file.content.trim_end());
        out.push_str("\n\n");
    }
}
