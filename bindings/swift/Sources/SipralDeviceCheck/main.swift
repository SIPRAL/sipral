// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

// The device-mode sequence an application runs around a call, on the
// machine's real devices, three times over: open the engine, ring a looped
// 8 kHz tone, stop it, put the speaker on the system's default output
// explicitly, close. Built by `swift build` with everything else and never
// run by the gate, because it needs a microphone and a loudspeaker; run by
// hand on a desk, and under the system's guard allocator to catch a write
// past the end of any buffer the audio path touches:
//
//   (cd bindings && swift build --product SipralDeviceCheck)
//   DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MallocScribble=1 \
//       bindings/.build/debug/SipralDeviceCheck
//
// SIPRAL_CHECK_ROUNDS sets how many rounds (3 by default). SIPRAL_CHECK_MIC
// and SIPRAL_CHECK_RINGER name, by a fragment of their names, a microphone
// and a ringer device to select before the first round, so that the same
// sequence runs with each role on a device of its own; SIPRAL_CHECK_SPEAKER
// names the device each round puts the speaker on, in place of the system's
// default output (a virtual loopback device keeps a desk quiet), and
// SIPRAL_CHECK_GAIN scales what is played (0.1 is a tenth). It prints
// one line per step and "PASS" at the end; anything thrown is printed and
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
    let stack = try SipralStack(audio: .device(activation: .automatic), bindHost: "127.0.0.1")
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
