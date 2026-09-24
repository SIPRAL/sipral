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
//!
//! `crates/sipral-aec-webrtc` is outside this workspace (its own `Cargo.toml`
//! says why) and links a C++ library nothing above discovers, so it gets its
//! own generated file instead of a row in the one above: `cargo run -p
//! sipral-license-gen -- --aec` writes
//! `crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt` from that crate's own
//! `Cargo.lock` and from the C++ sources `webrtc-audio-processing-sys`
//! vendors or fetches, and `-- --aec --check` is what `scripts/check.sh`
//! runs, once that crate itself has been built (`aec_out_dir` says why it
//! has to run after, not before).

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

/// `crates/sipral-aec-webrtc`'s own manifest directory, relative to the
/// workspace root — outside `[workspace] members`, so `--aec` is told where
/// to look rather than finding it the way [`shipped_dependencies`] does.
const AEC_CRATE_DIR: &str = "crates/sipral-aec-webrtc";

/// `--aec`'s generated file's path, relative to the workspace root. A file
/// of its own beside that crate, not a section of [`OUTPUT_FILE`]: the crate
/// ships separately from `sipral`/`sipral-ffi`, on whatever schedule an
/// application that depends on it chooses, so the notice belongs beside
/// what it is a notice for.
const AEC_OUTPUT_FILE: &str = "crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt";

/// The three crates.io components `crates/sipral-aec-webrtc/Cargo.lock`
/// pins that this tool reproduces licences for the same way [`run`] does for
/// [`SHIPPED_CRATES`] — read from that lockfile rather than `cargo tree`,
/// since a `cargo tree` from the AEC crate's own one-member workspace would
/// also walk into `sipral-media` and everything under it, which `run`
/// already covers and this file would then duplicate.
const AEC_REGISTRY_CRATES: &[&str] = &[
    "webrtc-audio-processing",
    "webrtc-audio-processing-sys",
    "webrtc-audio-processing-config",
];

/// Filenames, matched by prefix and case-insensitively, that carry a
/// component's own licence text at the root of its source tree.
const LICENCE_FILE_PREFIXES: &[&str] = &["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"];

/// A licence-bearing file found at a dependency's root: its name and content.
struct LicenceFile {
    name: String,
    content: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let check_only = args.iter().any(|a| a == "--check");
    let aec = args.iter().any(|a| a == "--aec");
    let (outcome, output_file, regenerate_hint) = if aec {
        (
            run_aec(check_only),
            AEC_OUTPUT_FILE,
            "cargo run -p sipral-license-gen -- --aec",
        )
    } else {
        (
            run(check_only),
            OUTPUT_FILE,
            "cargo run -p sipral-license-gen",
        )
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("{output_file} is stale; run `{regenerate_hint}` to update it");
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

/// [`run`]'s sibling for `crates/sipral-aec-webrtc`: the three crates.io
/// wrappers that crate's own `Cargo.lock` pins, read the same way `run`
/// reads [`SHIPPED_CRATES`]'s, plus the four components of the C++ library
/// they build from source, none of which is a crate at all so none of them
/// is found the same way.
///
/// The last of those four, abseil-cpp, is not vendored by any crate: meson
/// fetches it into that crate's own `target/` the first time it is built,
/// so this can only find its licence text after that build has actually
/// happened. `scripts/check.sh` calls `--aec --check` once it has built the
/// crate, not before, for that reason; run on its own before ever building
/// the crate, this returns [`aec_out_dir`]'s error rather than a stale pass.
fn run_aec(check_only: bool) -> Result<bool, String> {
    let root = workspace_root()?;
    let aec_root = root.join(AEC_CRATE_DIR);
    let registry_roots = registry_src_roots()?;

    let crate_versions = lockfile_versions(&aec_root.join("Cargo.lock"), AEC_REGISTRY_CRATES)?;
    let mut entries = String::new();
    let mut component_count = 0_usize;

    for (name, version) in &crate_versions {
        let dir = locate_crate_dir(&registry_roots, name, version).ok_or_else(|| {
            format!(
                "{name} {version} is not in a cached registry checkout; run `cargo fetch \
                 --manifest-path {AEC_CRATE_DIR}/Cargo.toml` first"
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
        render_entry(&mut entries, name, version, &license, &files);
        component_count += 1;
    }

    // webrtc-audio-processing-sys vendors the C++ library itself, and two of
    // its own third-party components, inside its own registry checkout --
    // found from the same directory as the crate entry just rendered, no
    // build needed for any of the three.
    let sys_version = crate_versions
        .iter()
        .find(|(name, _)| name == "webrtc-audio-processing-sys")
        .map(|(_, version)| version.clone())
        .ok_or_else(|| {
            format!("webrtc-audio-processing-sys is not in {AEC_CRATE_DIR}/Cargo.lock")
        })?;
    let sys_dir = locate_crate_dir(&registry_roots, "webrtc-audio-processing-sys", &sys_version)
        .ok_or_else(|| {
            format!(
                "webrtc-audio-processing-sys {sys_version} is not in a cached registry checkout"
            )
        })?;
    let vendored = sys_dir.join("webrtc-audio-processing");

    let webrtc_version = meson_project_version(&vendored.join("meson.build"))?;
    let webrtc_licence = read_single_licence_file(&vendored.join("webrtc"), "LICENSE")?;
    render_entry(
        &mut entries,
        "libwebrtc-audio-processing",
        &webrtc_version,
        "BSD-3-Clause",
        std::slice::from_ref(&webrtc_licence),
    );
    component_count += 1;

    let rnnoise_licence =
        read_single_licence_file(&vendored.join("webrtc/third_party/rnnoise"), "COPYING")?;
    render_entry(
        &mut entries,
        "rnnoise",
        "vendored with libwebrtc-audio-processing, no release of its own",
        "BSD-3-Clause",
        std::slice::from_ref(&rnnoise_licence),
    );
    component_count += 1;

    let pffft_licence =
        read_single_licence_file(&vendored.join("webrtc/third_party/pffft"), "LICENSE")?;
    render_entry(
        &mut entries,
        "pffft",
        "vendored with libwebrtc-audio-processing, no release of its own",
        "custom permissive (own text below, derived from the FFTPACKv5 licence)",
        std::slice::from_ref(&pffft_licence),
    );
    component_count += 1;

    // The one component meson fetches itself, at build time, rather than
    // this crate vendoring it.
    let (abseil_dir_name, abseil_version) =
        abseil_wrap_info(&vendored.join("subprojects/abseil-cpp.wrap"))?;
    let out_dir = aec_out_dir(&aec_root, &abseil_dir_name)?;
    let abseil_licence = read_single_licence_file(
        &out_dir
            .join("webrtc-audio-processing/subprojects")
            .join(&abseil_dir_name),
        "LICENSE",
    )?;
    render_entry(
        &mut entries,
        "abseil-cpp",
        &abseil_version,
        "Apache-2.0",
        std::slice::from_ref(&abseil_licence),
    );
    component_count += 1;

    let mut rendered = String::new();
    render_header_aec(&mut rendered, component_count);
    rendered.push_str(&entries);

    if check_only {
        let committed = fs::read_to_string(root.join(AEC_OUTPUT_FILE)).unwrap_or_default();
        return Ok(committed == rendered);
    }

    fs::write(root.join(AEC_OUTPUT_FILE), rendered)
        .map_err(|e| format!("writing {AEC_OUTPUT_FILE}: {e}"))?;
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

fn render_header_aec(out: &mut String, component_count: usize) {
    out.push_str(
        "sipral-aec-webrtc -- third-party licences\n\
         ==========================================\n\
         \n\
         Ship this file, or an equivalent notice screen, with any binary that\n\
         links crates/sipral-aec-webrtc: `LICENSE-COMMERCIAL.md` and\n\
         `LICENSING.md` require it, because the licences below require it\n\
         themselves. This is not a section of THIRD-PARTY-LICENSES.txt at the\n\
         workspace root, and nothing here repeats what is there: that file\n\
         covers `sipral`/`sipral-ffi`, which never depend on this crate, and\n\
         this one covers nothing they ship.\n\
         \n",
    );
    let _ = write!(
        out,
        "This lists every one of the {component_count} third-party components \
         crates/sipral-aec-webrtc actually links: the crates.io wrappers its \
         own Cargo.lock pins, and the C++ library they build from source -- \
         webrtc-audio-processing-sys's own vendored copy of \
         libwebrtc-audio-processing, the two third-party components bundled \
         inside it, and abseil-cpp, its one meson subproject, fetched rather \
         than vendored. For each one: its name, version, licence, and the \
         full licence text exactly as its own source ships it.\n\
         \n\
         This file is generated. Do not edit it by hand: run\n\
         `cargo run -p sipral-license-gen -- --aec` to regenerate it after any\n\
         change to `crates/sipral-aec-webrtc/Cargo.lock` or to the vendored\n\
         library's own version, and `cargo run -p sipral-license-gen -- --aec\n\
         --check`, which `scripts/check.sh` runs once the crate is built, to\n\
         check it is still current.\n\
         \n"
    );
}

/// Every `name`/`version` pair `--aec` asks for, read from a `Cargo.lock`'s
/// `[[package]]` blocks rather than `cargo tree` — see [`run_aec`] for why.
fn lockfile_versions(path: &Path, names: &[&str]) -> Result<Vec<(String, String)>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut found = Vec::new();
    for block in text.split("[[package]]").skip(1) {
        let Some(name) = field_value(block, "name") else {
            continue;
        };
        if !names.contains(&name.as_str()) {
            continue;
        }
        let Some(version) = field_value(block, "version") else {
            continue;
        };
        found.push((name, version));
    }
    found.sort();
    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|wanted| !found.iter().any(|(name, _)| name == wanted))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{}: missing {}",
            path.display(),
            missing.join(", ")
        ));
    }
    Ok(found)
}

/// The value of an unquoted `key = value` line, the shape a meson `.wrap`
/// file's `[wrap-file]` section writes rather than the quoted one
/// [`field_value`] reads a `Cargo.toml`/`Cargo.lock` line as.
fn ini_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

/// The single `LICENSE`/`COPYING` file a specific, known component ships at
/// its own root — unlike [`licence_files`], which scans a crate's root for
/// whichever of several prefixes it happens to use, this is for the C++
/// components inside `webrtc-audio-processing-sys`'s vendored tree, whose
/// exact filename this tool already knows from reading the source once.
fn read_single_licence_file(dir: &Path, filename: &str) -> Result<LicenceFile, String> {
    let path = dir.join(filename);
    let content =
        fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(LicenceFile {
        name: filename.to_string(),
        content,
    })
}

/// The `version :` argument of a vendored meson project's own top-level
/// `project(...)` call — `webrtc-audio-processing-sys`'s vendored copy of
/// libwebrtc-audio-processing declares it this way, and nowhere else in the
/// tree this tool can read carries that version.
fn meson_project_version(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("version") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim();
        if let Some(value) = rest.strip_prefix('\'')
            && let Some(end) = value.find('\'')
        {
            return Ok(value[..end].to_string());
        }
    }
    Err(format!("{}: no `version : '...'` line", path.display()))
}

/// abseil-cpp's directory name under `subprojects/` (its version baked into
/// the name, the way meson's wrap system names every subproject it fetches)
/// and, derived from that same name, its version on its own.
fn abseil_wrap_info(wrap_path: &Path) -> Result<(String, String), String> {
    let text = fs::read_to_string(wrap_path)
        .map_err(|e| format!("reading {}: {e}", wrap_path.display()))?;
    let directory = ini_value(&text, "directory")
        .ok_or_else(|| format!("{}: no `directory = ...` line", wrap_path.display()))?;
    let version = directory
        .strip_prefix("abseil-cpp-")
        .ok_or_else(|| format!("{directory}: does not start with \"abseil-cpp-\""))?
        .to_string();
    Ok((directory, version))
}

/// `webrtc-audio-processing-sys`'s build script's own `OUT_DIR`, the one
/// place abseil-cpp's fetched source — and its licence text with it —
/// actually exists: found under `crates/sipral-aec-webrtc/target`, since
/// that crate keeps its own target directory rather than sharing the
/// workspace's (its `Cargo.toml` says why). More than one build's output can
/// be sitting there at once (a stale profile from a previous toolchain,
/// say), so this asks for the one whose abseil-cpp `LICENSE` was written
/// most recently rather than the first one found.
fn aec_out_dir(aec_root: &Path, abseil_dir_name: &str) -> Result<PathBuf, String> {
    let how_to_build = format!(
        "build the crate first: cargo build --manifest-path {AEC_CRATE_DIR}/Cargo.toml (needs \
         meson and ninja)"
    );
    let target = aec_root.join("target");
    let profiles = fs::read_dir(&target)
        .map_err(|e| format!("reading {}: {e} — {how_to_build}", target.display()))?;

    let mut candidates: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    for profile in profiles {
        let profile = profile.map_err(|e| format!("reading {}: {e}", target.display()))?;
        let build_dir = profile.path().join("build");
        let Ok(entries) = fs::read_dir(&build_dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("reading {}: {e}", build_dir.display()))?;
            let name = entry.file_name();
            if !name
                .to_string_lossy()
                .starts_with("webrtc-audio-processing-sys-")
            {
                continue;
            }
            let licence = entry
                .path()
                .join("out/webrtc-audio-processing/subprojects")
                .join(abseil_dir_name)
                .join("LICENSE");
            if let Ok(metadata) = fs::metadata(&licence)
                && let Ok(modified) = metadata.modified()
            {
                candidates.push((entry.path().join("out"), modified));
            }
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(_, modified)| *modified)
        .map(|(out, _)| out)
        .ok_or_else(|| {
            format!(
                "no built webrtc-audio-processing-sys OUT_DIR under {}/target has abseil-cpp's \
                 LICENSE — {how_to_build}",
                aec_root.display()
            )
        })
}
