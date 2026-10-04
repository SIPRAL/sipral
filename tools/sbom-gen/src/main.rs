// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Write a CycloneDX 1.7 SBOM for one packaged artefact.
//!
//! `scripts/package/{wheels,nuget,aar,xcframework}.sh` each build
//! `sipral-ffi` with a specific feature list (`scripts/package/features.sh`)
//! for a specific target, then wrap the result into a shippable file. This
//! writes, beside that file, the inventory a buyer's security review reads:
//! every crate in `sipral-ffi`'s own normal dependency graph for that build,
//! plus the C components no `Cargo.toml` names because they are vendored
//! inside a `-sys` crate rather than declared as a dependency of it — today,
//! libopus inside `opusic-sys`, read the same way `sipral-license-gen --aec`
//! already reads a vendored C++ library's own licence file: found beside a
//! crate this tool already resolved, not assumed to exist.
//!
//! ```text
//! sbom-gen --crate sipral-ffi --features dtls,ice,stun --target aarch64-apple-darwin \
//!     --artifact-name sipral --artifact path/to/sipral-0.0.1-....whl \
//!     --out path/to/sipral-0.0.1-....whl.cdx.json
//! ```
//!
//! `--features opus,dtls,ice,stun` (`sipral-ffi`'s own defaults) additionally
//! writes a `libopus` component, resolved from whichever `opusic-sys` version
//! that dependency graph actually pins. Unlike `sipral-license-gen`'s
//! `THIRD-PARTY-LICENSES.txt`, this file is never committed — it is written
//! beside a build artefact, fresh on every packaging run, and carries that
//! run's own timestamp — so there is no "stale committed copy" for a
//! `--check` mode to compare against; there is only ever the one just
//! written. `--notices PATH` is the gate `scripts/check.sh` actually needs:
//! it asks whether this SBOM's crates.io components are exactly the crates
//! `PATH` (a `THIRD-PARTY-LICENSES.txt`) lists — no more, no fewer — which
//! only holds for the variant whose feature list matches that file's own
//! (`opus,dtls,ice,stun`, read with no feature flags at all).

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

/// The one crate this whole workspace vendors a C library inside without
/// declaring it: `opusic-sys` carries libopus's own sources under `opus/`,
/// with libopus's own version in `opus/package_version`
/// (`PACKAGE_VERSION="x.y.z"`) and libopus's own licence text at
/// `opus/COPYING` — byte-identical, in the version this was written against,
/// to `opusic-sys`'s own top-level `LICENSE`, which [`read_license_expression`]
/// already resolves for the `opusic-sys` component itself. A security review
/// matching this SBOM against a CVE feed needs "libopus 1.6.1" as its own
/// component: nothing published as a libopus advisory is filed against
/// "opusic-sys".
const OPUS_SYS_CRATE: &str = "opusic-sys";

/// A resolved crates.io dependency: its name, version and licence
/// expression, in the shape every component below is rendered from.
struct Component {
    name: String,
    version: String,
    license: String,
    /// `pkg:cargo/…` for a real crates.io crate, so the `--notices` check in
    /// [`run`] can tell a cargo-derived component from [`OPUS_SYS_CRATE`]'s
    /// synthetic libopus one, which `THIRD-PARTY-LICENSES.txt` never lists
    /// under that name.
    purl: Option<String>,
}

struct Args {
    krate: String,
    features: String,
    target: String,
    artifact_name: String,
    artifact_version: String,
    /// The packaged file to hash into `metadata.component.hashes`. Absent
    /// under a packaging script's own `--dry-run`, where `xcframework.sh`
    /// documents that the zip a host would publish is exactly what dry-run
    /// does not build; a hash of anything else would not be a hash of the
    /// artefact.
    artifact: Option<PathBuf>,
    out: PathBuf,
    notices: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!(
                "usage: sbom-gen --crate NAME --features LIST --target TRIPLE|all \
                 --artifact-name NAME --out FILE [--artifact FILE] [--notices FILE]"
            );
            return ExitCode::FAILURE;
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut krate = None;
    let mut features = None;
    let mut target = None;
    let mut artifact_name = None;
    let mut artifact_version = None;
    let mut artifact = None;
    let mut out = None;
    let mut notices = None;

    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--crate" => krate = Some(value()?),
            "--features" => features = Some(value()?),
            "--target" => target = Some(value()?),
            "--artifact-name" => artifact_name = Some(value()?),
            "--artifact-version" => artifact_version = Some(value()?),
            "--artifact" => artifact = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--notices" => notices = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        krate: krate.ok_or("--crate is required")?,
        features: features.unwrap_or_default(),
        target: target.ok_or("--target is required")?,
        artifact_name: artifact_name.ok_or("--artifact-name is required")?,
        artifact_version: artifact_version.unwrap_or_default(),
        artifact,
        out: out.ok_or("--out is required")?,
        notices,
    })
}

fn run(args: &Args) -> Result<(), String> {
    let root = workspace_root()?;
    let members = workspace_member_names(&root)?;
    let deps = crate_dependencies(&root, &args.krate, &args.features, &args.target)?;
    let registry_roots = registry_src_roots()?;

    let mut components = Vec::new();
    for (name, version) in &deps {
        if members.contains(name) {
            continue;
        }
        let dir = locate_crate_dir(&registry_roots, name, version).ok_or_else(|| {
            format!(
                "{name} {version} is not in a cached registry checkout; run `cargo fetch` first"
            )
        })?;
        let license = read_license_expression(&dir).ok_or_else(|| {
            format!("{name} {version}: no `license` or `license-file` field in its Cargo.toml")
        })?;
        components.push(Component {
            name: name.clone(),
            version: version.clone(),
            license: normalise_spdx(&license),
            purl: Some(format!("pkg:cargo/{name}@{version}")),
        });
    }

    let opus_version = deps
        .iter()
        .find(|(name, _)| name == OPUS_SYS_CRATE)
        .map(|(_, version)| version.clone());
    if let Some(sys_version) = opus_version {
        let sys_dir =
            locate_crate_dir(&registry_roots, OPUS_SYS_CRATE, &sys_version).ok_or_else(|| {
                format!("{OPUS_SYS_CRATE} {sys_version} is not in a cached registry checkout")
            })?;
        let sys_license = read_license_expression(&sys_dir).ok_or_else(|| {
            format!("{OPUS_SYS_CRATE} {sys_version}: no `license`/`license-file` field")
        })?;
        let libopus_version = read_opus_package_version(&sys_dir.join("opus/package_version"))?;
        components.push(Component {
            name: "libopus".to_string(),
            version: libopus_version,
            license: normalise_spdx(&sys_license),
            purl: None,
        });
    }

    let hash = args.artifact.as_deref().map(sha256_of).transpose()?;
    let rendered = render_sbom(args, &components, hash.as_deref());

    if let Some(notices_path) = &args.notices {
        let notices = fs::read_to_string(notices_path)
            .map_err(|e| format!("reading {}: {e}", notices_path.display()))?;
        let listed = notices_components(&notices);
        let sbom_cargo: BTreeSet<(String, String)> = components
            .iter()
            .filter(|c| c.purl.is_some())
            .map(|c| (c.name.clone(), c.version.clone()))
            .collect();
        if listed != sbom_cargo {
            let extra: Vec<_> = sbom_cargo.difference(&listed).collect();
            let missing: Vec<_> = listed.difference(&sbom_cargo).collect();
            let mut msg = format!(
                "{} does not list exactly what this SBOM's crate graph has:\n",
                notices_path.display()
            );
            for (name, version) in extra {
                let _ = writeln!(
                    msg,
                    "  in the SBOM, not in {}: {name} {version}",
                    notices_path.display()
                );
            }
            for (name, version) in missing {
                let _ = writeln!(
                    msg,
                    "  in {}, not in the SBOM: {name} {version}",
                    notices_path.display()
                );
            }
            return Err(msg);
        }
    }

    if let Some(parent) = args.out.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    fs::write(&args.out, rendered).map_err(|e| format!("writing {}: {e}", args.out.display()))?;
    Ok(())
}

/// `PACKAGE_VERSION="x.y.z"` out of `opusic-sys`'s vendored
/// `opus/package_version`, the one place libopus's own version is written in
/// the tree this tool can read without building anything.
fn read_opus_package_version(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    text.trim()
        .strip_prefix("PACKAGE_VERSION=\"")
        .and_then(|s| s.strip_suffix('"'))
        .map(str::to_string)
        .ok_or_else(|| format!("{}: no PACKAGE_VERSION=\"...\" line", path.display()))
}

/// Rust crates commonly write a licence field as a `/`-joined list
/// (`"MIT/Apache-2.0"`), which reads to a human but is not a legal SPDX
/// expression — SPDX joins alternatives with ` OR `. This is the one rewrite
/// this tool makes on a licence string; a `license-file` pointer
/// (`read_license_expression`'s `see <file>` form) is left as free text,
/// since there is no SPDX identifier to write in its place.
fn normalise_spdx(license: &str) -> String {
    if license.starts_with("see ") {
        return license.to_string();
    }
    license
        .split(['/', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// The crate name/version pairs a generated `THIRD-PARTY-LICENSES.txt`
/// lists, read off its own heading lines (`sipral-license-gen`'s
/// `render_entry`: `"{name} {version} -- {license}"`, alone on a line
/// between two rules of dashes) rather than the file's prose, which never
/// takes that exact shape.
fn notices_components(text: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let Some((head, _license)) = line.split_once(" -- ") else {
            continue;
        };
        let Some((name, version)) = head.rsplit_once(' ') else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        out.insert((name.to_string(), version.to_string()));
    }
    out
}

/// `sha256sum` (Linux) or `shasum -a 256` (macOS): both ship with the
/// platforms `scripts/package/` already targets, so this needs no crate of
/// its own for one digest.
fn sha256_of(path: &Path) -> Result<String, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| format!("{}: not valid UTF-8", path.display()))?;
    let output = Command::new("shasum")
        .args(["-a", "256", path_str])
        .output()
        .or_else(|_| Command::new("sha256sum").arg(path_str).output())
        .map_err(|e| format!("running shasum/sha256sum on {}: {e}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "hashing {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| format!("{}: shasum/sha256sum printed nothing", path.display()))
}

fn render_sbom(args: &Args, components: &[Component], artifact_sha256: Option<&str>) -> String {
    let timestamp = iso8601_now();
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"bomFormat\": \"CycloneDX\",");
    let _ = writeln!(out, "  \"specVersion\": \"1.7\",");
    let _ = writeln!(out, "  \"version\": 1,");
    let _ = writeln!(out, "  \"metadata\": {{");
    let _ = writeln!(out, "    \"timestamp\": \"{timestamp}\",");
    let _ = writeln!(out, "    \"component\": {{");
    let _ = writeln!(out, "      \"type\": \"library\",");
    let _ = writeln!(
        out,
        "      \"bom-ref\": \"{}@{}\",",
        json_escape(&args.artifact_name),
        json_escape(&args.artifact_version)
    );
    let _ = writeln!(
        out,
        "      \"name\": \"{}\",",
        json_escape(&args.artifact_name)
    );
    let _ = writeln!(
        out,
        "      \"version\": \"{}\",",
        json_escape(&args.artifact_version)
    );
    if let Some(sha256) = artifact_sha256 {
        let _ = writeln!(out, "      \"hashes\": [");
        let _ = writeln!(
            out,
            "        {{ \"alg\": \"SHA-256\", \"content\": \"{sha256}\" }}"
        );
        let _ = writeln!(out, "      ],");
    }
    let _ = writeln!(out, "      \"properties\": [");
    let _ = writeln!(
        out,
        "        {{ \"name\": \"sipral:cargo-features\", \"value\": \"{}\" }},",
        json_escape(&args.features)
    );
    let _ = writeln!(
        out,
        "        {{ \"name\": \"sipral:target\", \"value\": \"{}\" }}",
        json_escape(&args.target)
    );
    let _ = writeln!(out, "      ]");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "  }},");
    let _ = writeln!(out, "  \"components\": [");
    for (i, c) in components.iter().enumerate() {
        let comma = if i + 1 == components.len() { "" } else { "," };
        let _ = writeln!(out, "    {{");
        let _ = writeln!(out, "      \"type\": \"library\",");
        let bom_ref = c
            .purl
            .clone()
            .unwrap_or_else(|| format!("{}@{}", c.name, c.version));
        let _ = writeln!(out, "      \"bom-ref\": \"{}\",", json_escape(&bom_ref));
        let _ = writeln!(out, "      \"name\": \"{}\",", json_escape(&c.name));
        let _ = writeln!(out, "      \"version\": \"{}\",", json_escape(&c.version));
        if let Some(purl) = &c.purl {
            let _ = writeln!(out, "      \"purl\": \"{}\",", json_escape(purl));
        }
        let _ = writeln!(out, "      \"licenses\": [");
        if c.license.starts_with("see ") {
            let _ = writeln!(
                out,
                "        {{ \"license\": {{ \"name\": \"{}\" }} }}",
                json_escape(&c.license)
            );
        } else {
            let _ = writeln!(
                out,
                "        {{ \"expression\": \"{}\" }}",
                json_escape(&c.license)
            );
        }
        let _ = writeln!(out, "      ]");
        let _ = writeln!(out, "    }}{comma}");
    }
    let _ = writeln!(out, "  ]");
    out.push_str("}\n");
    out
}

/// No `time` crate for one field: seconds since the epoch, formatted by
/// hand, is precise enough for a document whose freshness matters at the
/// scale of "which build produced this," not to the second.
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to a
/// proleptic-Gregorian (year, month, day), the standard small closed-form
/// algorithm for this — chosen over a chrono dependency for one timestamp
/// field in a document nothing parses the date back out of.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
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

/// Every package name declared under a workspace member directory — this
/// tool's own dependency graph never lists one of these as a "third-party"
/// component, the same exclusion `sipral-license-gen` makes for the same
/// reason: it is Sipral's own code, under `LICENSE`, not a dependency.
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

fn read_package_name(manifest_path: &Path) -> Result<Option<String>, String> {
    let manifest = fs::read_to_string(manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    Ok(field_value(&manifest, "name"))
}

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

/// `cargo tree`, scoped to one crate's normal dependency edges for one
/// target, with an explicit feature list rather than whatever the crate's
/// manifest currently defaults to — the same reason
/// `scripts/package/features.sh` builds every artefact with
/// `--no-default-features --features "$FFI_FEATURES"` rather than trusting
/// the default list to still say what the caller means.
fn crate_dependencies(
    root: &Path,
    krate: &str,
    features: &str,
    target: &str,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut args = vec![
        "tree",
        "-e",
        "normal",
        "--prefix",
        "none",
        "--target",
        target,
        "-p",
        krate,
        "--no-default-features",
    ];
    if !features.is_empty() {
        args.push("--features");
        args.push(features);
    }

    let mut offline_args = args.clone();
    offline_args.push("--offline");
    let mut output = Command::new("cargo")
        .current_dir(root)
        .args(&offline_args)
        .output()
        .map_err(|e| format!("running cargo tree: {e}"))?;
    if !output.status.success() {
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
        deps.insert((name.to_string(), version.to_string()));
    }
    Ok(deps)
}

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

fn read_license_expression(crate_dir: &Path) -> Option<String> {
    let manifest = fs::read_to_string(crate_dir.join("Cargo.toml")).ok()?;
    if let Some(license) = field_value(&manifest, "license") {
        return Some(license);
    }
    field_value(&manifest, "license-file").map(|file| format!("see {file}"))
}
