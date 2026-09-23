# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# interop/pipewire/run.sh's sibling, for the platform where the lab's audio
# is real hardware rather than a container's own virtual cables: builds the
# harness with the wasapi feature, and drives a call to the lab's echo
# extension whose microphone and earpiece are VB-CABLE's two WASAPI
# endpoints (interop/harness/src/wasapi.rs says what is played where and why
# the tone coming back proves the whole path).
#
#   powershell -NoProfile -File interop\wasapi\run.ps1 -ListDevices
#       just the machine's own audio endpoints, id included -- the first
#       thing to run on a machine whose cable is not named the way VB-CABLE's
#       installer usually names it, or that has more than one
#
#   powershell -NoProfile -File interop\wasapi\run.ps1 -ServerHost 192.168.3.172
#       the crate's own tests, then the call -- `scripts/lab.sh wasapi up`,
#       run first on the machine that hosts the lab, says what host and port
#       to give here
#
# Needs cargo on the path (rust-toolchain.toml pins the version; rustup
# installs it on first use) and VB-CABLE already installed -- this script
# installs nothing.
#
# The default earpiece/microphone match (`interop/harness/src/wasapi.rs`'s
# `DEFAULT_EARPIECE_NAME`/`DEFAULT_MIC_NAME`) assumes VB-CABLE's own naming;
# a paid multi-channel edition names its render side differently ("CABLE In
# 16 Ch", say, not "CABLE Input") and needs $env:SIPRAL_WASAPI_EARPIECE_ID
# (or _NAME) set to what -ListDevices printed.
param(
    [string]$ServerHost = $(if ($env:SIPRAL_SERVER_HOST) { $env:SIPRAL_SERVER_HOST } else { "192.168.3.172" }),
    [int]$ServerPort = $(if ($env:SIPRAL_SERVER_PORT) { [int]$env:SIPRAL_SERVER_PORT } else { 5062 }),
    [switch]$ListDevices
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")

$env:CARGO_BUILD_JOBS = $(if ($env:CARGO_BUILD_JOBS) { $env:CARGO_BUILD_JOBS } else { "4" })

Write-Host "building the harness (wasapi feature)"
cargo build --locked --release -p sipral-interop --features wasapi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$harness = "target\release\sipral-interop.exe"

if ($ListDevices) {
    & $harness --list-audio-devices
    exit $LASTEXITCODE
}

Write-Host "the crate, against real endpoints:"
cargo test --locked -p sipral-io-wasapi -- --include-ignored --nocapture --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "the machine's own audio endpoints:"
& $harness --list-audio-devices

Write-Host ""
Write-Host "a call to $ServerHost`:$ServerPort, through them:"
$env:SIPRAL_FLOWS = "wasapi"
& $harness $ServerHost $ServerPort
exit $LASTEXITCODE
