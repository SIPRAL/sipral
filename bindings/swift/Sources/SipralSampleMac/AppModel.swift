// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
import Sipral
import Observation

/// The sample's state: one stack, one account, at most one call. Device
/// mode runs the audio; the sample only picks devices, volume and mute.
///
/// Fields can come from the environment: `SIPRAL_SAMPLE_AOR`,
/// `SIPRAL_SAMPLE_REGISTRAR_ADDRESS`, `SIPRAL_SAMPLE_REGISTRAR`,
/// `SIPRAL_SAMPLE_AUTH_USER`, `SIPRAL_SAMPLE_AUTH_PASSWORD`,
/// `SIPRAL_SAMPLE_TARGET`; `SIPRAL_SAMPLE_CALL=1` registers and calls at
/// launch.
@Observable
@MainActor
final class AppModel {
    enum Status: Equatable {
        case idle
        case registering
        case registered
        case failed(String)
    }

    struct Incoming: Equatable {
        let event: SipralEvent
        let caller: String
        let detail: String

        static func == (lhs: Incoming, rhs: Incoming) -> Bool { lhs.event.call == rhs.event.call }
    }

    private static let environment = ProcessInfo.processInfo.environment

    var aor = environment["SIPRAL_SAMPLE_AOR"] ?? "sip:alice@sipral.invalid"
    var registrarAddress = environment["SIPRAL_SAMPLE_REGISTRAR_ADDRESS"] ?? "127.0.0.1:5060"
    var registrar = environment["SIPRAL_SAMPLE_REGISTRAR"] ?? ""
    var authUser = environment["SIPRAL_SAMPLE_AUTH_USER"] ?? ""
    var authPassword = environment["SIPRAL_SAMPLE_AUTH_PASSWORD"] ?? ""
    var target = environment["SIPRAL_SAMPLE_TARGET"] ?? ""

    private(set) var status: Status = .idle
    private(set) var callState: SipralCallState?
    private(set) var onHold = false
    private(set) var incoming: Incoming?
    private(set) var log: [String] = []

    // the devices, as the library's engine lists and runs them
    private(set) var devices: [SipralAudioDevice] = []
    private(set) var speaker: UInt32?
    private(set) var inputLevel = 0.0
    private(set) var outputLevel = 0.0
    private(set) var echoCancelled = false
    private(set) var microphoneMuted = false
    private(set) var speakerMuted = false
    private(set) var microphoneGain = 1.0
    private(set) var speakerVolume = 1.0

    private var stack: SipralStack?
    private var account: Account?
    private var call: Call?
    private var eventTask: Task<Void, Never>?
    private var callEventTask: Task<Void, Never>?
    private var meterTask: Task<Void, Never>?
    private let network = NetworkWatcher()

    func append(_ line: String) {
        print(line)
        fflush(stdout)
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }

    func start() {
        guard Self.environment["SIPRAL_SAMPLE_CALL"] == "1", stack == nil else { return }
        register()
        placeCall()
    }

    /// The stack, bound on the address this Mac reaches the registrar from.
    private func openStack() throws -> SipralStack {
        if let stack { return stack }
        let here = NetworkWatcher.current(toward: registrarAddress)
        let opened = try SipralStack(bindHost: here.address ?? "127.0.0.1", network: here)
        stack = opened
        append("listening on \(opened.bindAddress), audio \(opened.audioMode)")
        let events = opened.events()
        eventTask = Task { [weak self] in
            for await event in events {
                await self?.handleStackEvent(event)
            }
        }
        network.start(toward: registrarAddress) { [weak self] now in
            Task { @MainActor in self?.networkChanged(now) }
        }
        readDevices()
        meterTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.readMeters()
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        return opened
    }

    func register() {
        do {
            let stack = try openStack()
            let account = try stack.addAccount(
                aor: aor,
                registrarAddress: registrarAddress,
                registrar: registrar.isEmpty ? nil : registrar,
                authUser: authUser.isEmpty ? nil : authUser,
                authPassword: authPassword.isEmpty ? nil : authPassword
            )
            self.account = account
            if !registrar.isEmpty {
                status = .registering
                try account.register()
            } else {
                status = .registered
            }
        } catch {
            status = .failed("\(error)")
        }
    }

    func placeCall() {
        guard let stack, let account else { return }
        do {
            let host = UDPSocket.parse(stack.bindAddress).host
            let call = try stack.placeCall(account: account, target: target, mediaHost: host)
            attach(call)
        } catch {
            append("call failed: \(error)")
        }
    }

    func answer() {
        guard let stack, let incoming else { return }
        self.incoming = nil
        try? stack.audio?.stopRinging()
        var attachedCall: Call?
        do {
            // attached before answering, so no event is missed
            let host = UDPSocket.parse(stack.bindAddress).host
            let call = try stack.takeIncomingCall(incoming.event, mediaHost: host)
            attach(call)
            attachedCall = call
            try call.answer()
        } catch {
            append("answer failed: \(error)")
            // a failed answer must not stay the current call
            if let attachedCall, self.call === attachedCall {
                callEventTask?.cancel()
                callEventTask = nil
                self.call = nil
                callState = nil
            }
            attachedCall?.close()
        }
    }

    func decline() {
        guard let stack, let incoming else { return }
        self.incoming = nil
        try? stack.audio?.stopRinging()
        try? stack.rejectCall(incoming.event, code: 603)
    }

    func hangup() {
        try? call?.hangup(reason: .normalClearing)
    }

    func toggleHold() {
        guard let call else { return }
        do {
            if onHold {
                try call.resume()
            } else {
                try call.hold()
            }
        } catch {
            append("hold/resume failed: \(error)")
        }
    }

    func sendDigit(_ digit: String) {
        try? call?.sendDtmf(digit)
    }

    // MARK: - the devices

    func selectSpeaker(_ id: UInt32?) {
        do {
            try stack?.audio?.select(id, for: .speaker)
        } catch {
            append("cannot put the speaker there: \(error)")
        }
        readDevices()
    }

    func setSpeakerVolume(_ volume: Double) {
        try? stack?.audio?.setGain(volume, for: .output)
        speakerVolume = volume
    }

    func setMicrophoneGain(_ gain: Double) {
        try? stack?.audio?.setGain(gain, for: .input)
        microphoneGain = gain
    }

    func setMicrophoneMuted(_ muted: Bool) {
        try? stack?.audio?.setMuted(muted, for: .input)
        microphoneMuted = muted
    }

    func setSpeakerMuted(_ muted: Bool) {
        try? stack?.audio?.setMuted(muted, for: .output)
        speakerMuted = muted
    }

    private func readDevices() {
        guard let audio = stack?.audio else { return }
        devices = (try? audio.refresh()) ?? []
        speaker = try? audio.selection(for: .speaker).selected
    }

    private func readMeters() {
        guard let audio = stack?.audio else { return }
        inputLevel = (try? audio.level(for: .input)) ?? 0
        outputLevel = (try? audio.level(for: .output)) ?? 0
        echoCancelled = (try? audio.status().systemEchoCancellation) ?? false
        loudest = (max(loudest.input, inputLevel), max(loudest.output, outputLevel))
    }

    /// The highest either meter read during the call, said in the log when
    /// it ends.
    private var loudest = (input: 0.0, output: 0.0)

    /// Two seconds of a 425 Hz tone and four of silence, at 8 kHz: the ring
    /// the library plays on the ringer's device while a call waits.
    private static let ringTone: [Int16] = (0..<48_000).map { sample in
        guard sample < 16_000 else { return 0 }
        return Int16(6_000 * sin(2 * Double.pi * 425 * Double(sample) / 8_000))
    }

    // MARK: - the network

    private func networkChanged(_ now: SipralStack.Network) {
        guard let stack else { return }
        do {
            let recovery = try stack.networkChanged(to: now)
            if recovery != .nothing {
                append("network now \(now.address ?? "gone") on \(now.interface ?? "-"): \(recovery)")
            }
        } catch {
            append("network change failed: \(error)")
        }
    }

    // MARK: - events

    private func attach(_ call: Call) {
        self.call = call
        callState = try? call.state
        callEventTask?.cancel()
        let events = call.events()
        callEventTask = Task { [weak self] in
            for await event in events {
                await self?.handleCallEvent(event, call: call)
            }
        }
    }

    private func handleStackEvent(_ event: SipralEvent) async {
        if event.kind == .audioDevicesChanged, let change = event.audioData {
            append("devices: \(change.change.map { "\($0)" } ?? "?") by the \(change.origin.map { "\($0)" } ?? "?")")
            if change.origin == .system {
                readDevices()
            }
            return
        }
        append(event.kindName)
        if event.kind == .registrationChanged {
            switch event.registrationData?.state {
            case .some(.registered): status = .registered
            case .some(.failed): status = .failed("registration failed")
            default: break
            }
        }
        if event.kind == .incomingCall {
            ringFor(event)
        }
    }

    /// Show the caller (asserted identity if trusted, else `From`), ring, and
    /// auto-answer when asked to.
    private func ringFor(_ event: SipralEvent) {
        guard let stack, call == nil else {
            try? self.stack?.rejectCall(event, code: 486)
            return
        }
        let identity = try? stack.callerIdentity(of: event)
        let answering = try? stack.answering(of: event)
        let caller = identity?.asserted?.displayName ?? identity?.asserted?.uri
            ?? event.callData?.fromDisplay ?? event.callData?.fromUri ?? "unknown"
        var detail: [String] = []
        if let diverted = identity?.diversions.first {
            detail.append("diverted from \(diverted.uri) (\(diverted.reason ?? "no reason"))")
        }
        if identity?.privacy.contains(.id) == true {
            detail.append("number withheld")
        }
        incoming = Incoming(event: event, caller: caller, detail: detail.joined(separator: ", "))
        try? stack.audio?.ring(Self.ringTone, sampleRate: 8_000)
        if let after = answering?.answerAfterMs {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: after * 1_000_000)
                self?.answer()
            }
        }
    }

    private func handleCallEvent(_ event: SipralEvent, call: Call) async {
        callState = try? call.state
        if let data = event.callData {
            onHold = data.heldHere
        }
        if event.kind == .callAddressWanted {
            do {
                try call.moveMedia()
                append("call offered at its new address")
            } catch {
                append("the call could not move: \(error)")
            }
        }
        if event.kind == .callEnded {
            if let cause = event.callData?.endCause {
                append("ended: \(cause.text ?? "SIP \(cause.sip ?? 0) / Q.850 \(cause.q850 ?? 0)")")
            }
            append(String(format: "loudest: microphone %.3f, speaker %.3f", loudest.input, loudest.output))
            loudest = (0, 0)
            self.call?.close()
            self.call = nil
            callState = nil
        }
    }
}
