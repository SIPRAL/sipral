#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The iPhone sample, bindings/swift/samples/SipralPhone: built for the
# simulator, built for a phone, and archived and exported for TestFlight,
# over the XCFramework scripts/package/xcframework.sh builds from this tree.
#
#   scripts/package/ios-app.sh                     the XCFramework, the icon,
#                                                  a simulator build and a
#                                                  device build (signed when
#                                                  a team is given, else only
#                                                  compiled)
#   ... --test UDID                                and the application's own
#                                                  tests on that simulator
#   ... --archive                                  and an archive, exported as
#                                                  an IPA for App Store
#                                                  Connect; needs a team
#   ... --reuse-xcframework                        the XCFramework already in
#                                                  DIR/apple, if there is one
#   ... --out DIR                                  default target/ios-app
#
# The team is the signer's and never in the tree: DEVELOPMENT_TEAM (or
# SIPRAL_TEAM_ID) in the environment is passed to xcodebuild with
# -allowProvisioningUpdates, which lets Xcode create the App ID, the
# certificates and the profiles the account lacks. SIPRAL_PHONE_BUNDLE_ID
# replaces org.sipral.phone. Nothing here uploads: the IPA's path and the
# command that would are printed, and the upload is the owner's.
#
# The project names its Swift package by path, DIR/apple/spm, where
# xcframework.sh prints the Sipral module over the XCFramework it built, so
# the application links the library this tree builds, not a release's. The
# icon is drawn from assets/sipral-mark.svg into the asset catalog (git
# ignores the PNG): the mark on its ground, one cell of clear space round it.
set -uo pipefail

found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/../.."
ROOT="$PWD"

OUT="$ROOT/target/ios-app"
TEST_UDID=""
ARCHIVE=0
REUSE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --test) TEST_UDID="$2"; shift 2 ;;
        --archive) ARCHIVE=1; shift ;;
        --reuse-xcframework) REUSE=1; shift ;;
        *) printf 'unknown argument: %s\nusage: ios-app.sh [--out DIR] [--test UDID] [--archive] [--reuse-xcframework]\n' "$1" >&2; exit 2 ;;
    esac
done
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
APP_DIR="$ROOT/bindings/swift/samples/SipralPhone"
PROJECT="$APP_DIR/SipralPhone.xcodeproj"
DERIVED="$OUT/derived"
TEAM="${DEVELOPMENT_TEAM:-${SIPRAL_TEAM_ID:-}}"
BUNDLE_ID="${SIPRAL_PHONE_BUNDLE_ID:-org.sipral.phone}"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }
stop() { printf '\nios-app.sh: failed\n'; exit 1; }

[ "$(uname -s)" = "Darwin" ] || { fail "ios-app.sh runs only on macOS: the application needs Xcode"; stop; }
command -v xcodebuild >/dev/null 2>&1 || { fail "xcodebuild not found (Xcode, not just the Command Line Tools)"; stop; }

step "one version"
"$ROOT/scripts/version.sh" --check || stop
VERSION="$("$ROOT/scripts/version.sh")"
# A build number App Store Connect has not seen: the minute it was made.
BUILD_NUMBER="$(date -u +%Y%m%d%H%M)"

# The project's package reference is this path; another --out leaves the
# project pointing at the default one.
if [ "$OUT" != "$ROOT/target/ios-app" ]; then
    note "the project reads its package from target/ios-app/apple/spm, not $OUT/apple/spm"
fi

step "CSipral.xcframework and the Sipral package over it"
if [ "$REUSE" -eq 1 ] && [ -f "$OUT/apple/spm/Package.swift" ] && [ -d "$OUT/apple/CSipral.xcframework" ]; then
    pass "reused $OUT/apple"
    # the module's sources are copied again, so a change to them is built
    rm -f "$OUT/apple/spm/Sources/Sipral/"*.swift
    cp "$ROOT"/bindings/swift/Sources/Sipral/*.swift "$OUT/apple/spm/Sources/Sipral/"
    pass "bindings/swift/Sources/Sipral copied into $OUT/apple/spm again"
elif "$ROOT/scripts/package/xcframework.sh" --out "$OUT/apple" --dry-run >"$OUT/xcframework.log" 2>&1; then
    pass "xcframework.sh --out $OUT/apple --dry-run"
else
    fail "xcframework.sh --out $OUT/apple --dry-run:"
    tail -30 "$OUT/xcframework.log" | sed 's/^/        /'
    stop
fi

step "the icon, from assets/sipral-mark.svg"
ICON="$APP_DIR/SipralPhone/Assets.xcassets/AppIcon.appiconset/AppIcon.png"
# The SVG is nine-cell grid of plain rectangles; each is drawn as it is
# written, on the brand's ground, with one cell of clear space on every
# side, into a 1024-pixel square with no transparency, as App Store icons
# must be.
cat >"$OUT/icon.swift" <<'EOF'
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let arguments = CommandLine.arguments
let svg = try String(contentsOfFile: arguments[1], encoding: .utf8)
func number(_ name: String, _ tag: String) -> Double? {
    guard let range = tag.range(of: "\(name)=\"") else { return nil }
    return Double(tag[range.upperBound...].prefix { $0 != "\"" })
}
func colour(_ hex: Substring) -> CGColor {
    let value = Int(hex, radix: 16) ?? 0
    return CGColor(
        srgbRed: Double((value >> 16) & 0xff) / 255, green: Double((value >> 8) & 0xff) / 255,
        blue: Double(value & 0xff) / 255, alpha: 1
    )
}
let tags = svg.components(separatedBy: "<rect").dropFirst().map { $0.prefix { $0 != ">" } }.map(String.init)
let box = 108.0, cell = 34.0, side = 1024
let scale = Double(side) / (box + 2 * cell)
guard let context = CGContext(
    data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
) else { exit(1) }
context.setFillColor(colour("f3f2f2"))
context.fill(CGRect(x: 0, y: 0, width: side, height: side))
for tag in tags {
    guard let x = number("x", tag), let y = number("y", tag), let w = number("width", tag), let h = number("height", tag),
          let fill = tag.range(of: "fill=\"#") else { exit(1) }
    context.setFillColor(colour(tag[fill.upperBound...].prefix(6)))
    // SVG counts y down from the top, Core Graphics up from the bottom.
    context.fill(CGRect(
        x: (x + cell) * scale, y: Double(side) - (y + cell + h) * scale, width: w * scale, height: h * scale
    ))
}
guard let image = context.makeImage(),
      let out = CGImageDestinationCreateWithURL(URL(fileURLWithPath: arguments[2]) as CFURL, UTType.png.identifier as CFString, 1, nil)
else { exit(1) }
CGImageDestinationAddImage(out, image, nil)
exit(CGImageDestinationFinalize(out) && tags.count == 7 ? 0 : 1)
EOF
if xcrun --sdk macosx swift "$OUT/icon.swift" "$ROOT/assets/sipral-mark.svg" "$ICON" >"$OUT/icon.log" 2>&1; then
    pass "AppIcon.png, $(sips -g pixelWidth -g hasAlpha "$ICON" 2>/dev/null | awk '/pixelWidth/ {w=$2} /hasAlpha/ {a=$2} END {print w " pixels, alpha " a}')"
else
    fail "the icon could not be drawn:"
    tail -20 "$OUT/icon.log" | sed 's/^/        /'
fi

common=(-project "$PROJECT" -scheme SipralPhone -derivedDataPath "$DERIVED" SIPRAL_PHONE_BUNDLE_ID="$BUNDLE_ID"
    MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD_NUMBER")

step "the simulator"
if xcodebuild build "${common[@]}" -destination 'generic/platform=iOS Simulator' >"$OUT/simulator.log" 2>&1; then
    APP="$DERIVED/Build/Products/Debug-iphonesimulator/SipralPhone.app"
    pass "xcodebuild build, generic/platform=iOS Simulator: $APP"
else
    fail "xcodebuild build for the simulator:"
    grep -E 'error:|FAILED' "$OUT/simulator.log" | head -30 | sed 's/^/        /'
fi

if [ -n "$TEST_UDID" ]; then
    step "the application's tests, on simulator $TEST_UDID"
    if xcodebuild test "${common[@]}" -destination "platform=iOS Simulator,id=$TEST_UDID" >"$OUT/test.log" 2>&1; then
        pass "xcodebuild test: $(grep -E 'Executed [0-9]+ tests' "$OUT/test.log" | tail -1 | sed 's/^[[:space:]]*//')"
    else
        fail "xcodebuild test:"
        grep -E 'error:|failed|Executed' "$OUT/test.log" | head -30 | sed 's/^/        /'
    fi
fi

step "a phone (generic/platform=iOS)"
if [ -z "$TEAM" ]; then
    # Compiled and linked for the device, every availability check with it,
    # and not signed: there is nobody to sign it as.
    if xcodebuild build "${common[@]}" -configuration Release -destination 'generic/platform=iOS' \
        CODE_SIGNING_ALLOWED=NO >"$OUT/device.log" 2>&1; then
        pass "xcodebuild build, Release, generic/platform=iOS, unsigned (no DEVELOPMENT_TEAM given)"
    else
        fail "xcodebuild build for a phone:"
        grep -E 'error:|FAILED' "$OUT/device.log" | head -30 | sed 's/^/        /'
    fi
else
    security find-identity -v -p codesigning 2>/dev/null | found 'Apple Development' \
        && pass "an Apple Development identity is in the keychain" \
        || note "no Apple Development identity in the keychain; Xcode is allowed to create one"
    if xcodebuild build "${common[@]}" -destination 'generic/platform=iOS' -allowProvisioningUpdates \
        DEVELOPMENT_TEAM="$TEAM" >"$OUT/device.log" 2>&1; then
        pass "xcodebuild build, generic/platform=iOS, signed for development"
    else
        fail "xcodebuild build for a phone, signed:"
        grep -E 'error:|FAILED' "$OUT/device.log" | head -30 | sed 's/^/        /'
        found -i 'no devices' "$OUT/device.log" \
            && note "a development profile needs a registered iPhone: connect it once with Xcode open, then run this again"
    fi
fi

if [ "$ARCHIVE" -eq 1 ]; then
    step "the archive and the IPA for App Store Connect"
    if [ -z "$TEAM" ]; then
        fail "--archive needs DEVELOPMENT_TEAM (or SIPRAL_TEAM_ID) in the environment"
    else
        ARCHIVE_PATH="$OUT/SipralPhone.xcarchive"
        EXPORT="$OUT/export"
        rm -rf "$ARCHIVE_PATH" "$EXPORT"
        # Archived unsigned: a development signature would need a profile,
        # and a profile a registered phone. The application is then signed
        # ad hoc with its entitlements, aps-environment among them, which
        # the export reads to ask for a distribution profile with push; the
        # export signs it with that.
        if xcodebuild archive "${common[@]}" -destination 'generic/platform=iOS' -archivePath "$ARCHIVE_PATH" \
            DEVELOPMENT_TEAM="$TEAM" CODE_SIGNING_ALLOWED=NO >"$OUT/archive.log" 2>&1 \
            && codesign --force --sign - --entitlements "$APP_DIR/SipralPhone.entitlements" \
                "$ARCHIVE_PATH/Products/Applications/SipralPhone.app" >>"$OUT/archive.log" 2>&1; then
            pass "xcodebuild archive: $ARCHIVE_PATH, version $VERSION ($BUILD_NUMBER), signed ad hoc with its entitlements"
        else
            fail "xcodebuild archive:"
            grep -E 'error:|FAILED' "$OUT/archive.log" | head -30 | sed 's/^/        /'
        fi
        cat >"$OUT/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>app-store-connect</string>
	<key>destination</key>
	<string>export</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>teamID</key>
	<string>$TEAM</string>
	<key>manageAppVersionAndBuildNumber</key>
	<false/>
	<key>uploadSymbols</key>
	<true/>
</dict>
</plist>
EOF
        if [ -d "$ARCHIVE_PATH" ] && xcodebuild -exportArchive -archivePath "$ARCHIVE_PATH" -exportPath "$EXPORT" \
            -exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates >"$OUT/export.log" 2>&1 \
            && [ -f "$EXPORT/SipralPhone.ipa" ]; then
            pass "exported for App Store Connect: $EXPORT/SipralPhone.ipa"
            rm -rf "$OUT/ipa"
            unzip -q "$EXPORT/SipralPhone.ipa" -d "$OUT/ipa"
            entitlements=$(codesign -d --entitlements :- "$OUT/ipa/Payload/SipralPhone.app" 2>/dev/null)
            if printf '%s' "$entitlements" | found -A1 'aps-environment' && printf '%s' "$entitlements" | found '>production<'; then
                pass "the IPA is entitled to production pushes (aps-environment production)"
            else
                fail "the IPA carries no aps-environment of production: PushKit would never deliver to it"
            fi
            printf '\n  not run: the upload is the owner'"'"'s. In Xcode, Window > Organizer, the archive above,\n'
            printf '  Distribute App > TestFlight & App Store; or the IPA dragged into Transporter; or\n'
            printf '  xcrun altool --upload-app -f "%s" -t ios --apiKey KEY --apiIssuer ISSUER\n' "$EXPORT/SipralPhone.ipa"
        elif [ -d "$ARCHIVE_PATH" ]; then
            fail "xcodebuild -exportArchive:"
            grep -E 'error|Error' "$OUT/export.log" | head -30 | sed 's/^/        /'
        fi
    fi
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'ios-app.sh: done, %s\n' "$OUT"; exit 0; }
printf 'ios-app.sh: failed\n'; exit 1
