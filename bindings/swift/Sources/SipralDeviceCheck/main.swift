// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// The device-mode sequence around a call, on real devices, repeated: open,
// ring, stop, select the default speaker, close. Needs real devices, so it
// is run by hand, ideally under the guard allocator:
//
//   (cd bindings && swift build --product SipralDeviceCheck)
//   DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MallocScribble=1 \
//       bindings/.build/debug/SipralDeviceCheck
//
// SIPRAL_CHECK_ROUNDS: rounds (default 3). SIPRAL_CHECK_MIC,
// SIPRAL_CHECK_RINGER, SIPRAL_CHECK_SPEAKER: device name fragments
// (a virtual loopback speaker keeps a desk quiet). SIPRAL_CHECK_GAIN scales
// playback. SIPRAL_CHECK_RESELECT moves the microphone away and back each
// round, reopening the voice unit mid-round. SIPRAL_CHECK_PROBE_MS allows
// slower opens under the guard allocator. Prints "PASS", or the error and
// exits 1.

import Foundation
import Sipral

setvbuf(stdout, nil, _IOLBF, 0)

func named(_ variable: String, serving role: SipralAudioRole, in devices: [SipralAudioDevice]) -> SipralAudioDevice? {
    guard let fragment = ProcessInfo.processInfo.environment[variable], !fragment.isEmpty else {
        return nil
    }
    return devices.first { $0.canServe(role) && $0.name.contains(fragment) }
}

let rounds = Int(ProcessInfo.processInfo.environment["SIPRAL_CHECK_ROUNDS"] ?? "") ?? 3

do {
    let probeMs = UInt64(ProcessInfo.processInfo.environment["SIPRAL_CHECK_PROBE_MS"] ?? "") ?? 0
    let stack = try SipralStack(
        audio: .device(activation: .automatic), bindHost: "127.0.0.1", audioProbeMs: probeMs)
    guard let audio = stack.audio else {
        print("no device mode in this build of the library")
        exit(2)
    }
    let devices = try audio.refresh()
    for device in devices {
        print("device \(device.id) \(device.name) in=\(device.inputChannels) out=\(device.outputChannels)"
            + " defaultIn=\(device.isDefaultInput) defaultOut=\(device.isDefaultOutput)")
    }
    let chosen: [(String, SipralAudioRole)] = [
        ("SIPRAL_CHECK_SPEAKER", .speaker), ("SIPRAL_CHECK_MIC", .microphone), ("SIPRAL_CHECK_RINGER", .ringer),
    ]
    for (variable, role) in chosen {
        if let device = named(variable, serving: role, in: devices) {
            try audio.select(device, for: role)
            print("selected \(device.name) for \(role)")
        }
    }
    if let gain = Double(ProcessInfo.processInfo.environment["SIPRAL_CHECK_GAIN"] ?? "") {
        try audio.setGain(gain, for: .output)
        print("output gain \(gain)")
    }
    let speaker = named("SIPRAL_CHECK_SPEAKER", serving: .speaker, in: devices)
        ?? devices.first(where: { $0.isDefaultOutput })
    let microphone = named("SIPRAL_CHECK_MIC", serving: .microphone, in: devices)
    let reselect = !(ProcessInfo.processInfo.environment["SIPRAL_CHECK_RESELECT"] ?? "").isEmpty
    // one second of a 440 Hz tone at 8 kHz, which is what a ring is made of
    let tone = (0..<8000).map { Int16(3000 * sin(Double($0) * 2 * .pi * 440 / 8000)) }
    for round in 1...rounds {
        print("round \(round): activate")
        try audio.activate()
        try audio.ring(tone, sampleRate: 8000, looped: true)
        Thread.sleep(forTimeInterval: 1.5)
        print("round \(round): \(try audio.status())")
        try audio.stopRinging()
        if let speaker {
            try audio.select(speaker, for: .speaker)
            print("round \(round): speaker on \(speaker.name)")
        }
        if reselect, let microphone {
            try audio.select(nil as AudioDevice?, for: .microphone)
            Thread.sleep(forTimeInterval: 0.5)
            try audio.select(microphone, for: .microphone)
            print("round \(round): microphone on the system's default and back on \(microphone.name)")
        }
        Thread.sleep(forTimeInterval: 1.0)
        try audio.deactivate()
        print("round \(round): deactivated")
    }
    stack.close()
    print("PASS")
} catch {
    print("FAIL: \(error)")
    exit(1)
}
