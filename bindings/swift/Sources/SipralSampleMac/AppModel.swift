// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import Sipral
import Observation

/// The skeleton sample's whole state: one stack, one account, at most one
/// call at a time. Not a product -- `docs/08-ffi.md`, "Swift" calls this out
/// as the layer's real proof: "what is not printed is the platform work,
/// and it is what the binding will actually earn its place for."
@Observable
@MainActor
final class AppModel {
    enum Status: Equatable {
        case idle
        case registering
        case registered
        case failed(String)
    }

    var aor = "sip:alice@sipral.invalid"
    var registrarAddress = "127.0.0.1:5060"
    var registrar = ""
    var authUser = ""
    var authPassword = ""
    var target = ""
    var digits = ""

    private(set) var status: Status = .idle
    private(set) var callState: SipralCallState?
    private(set) var onHold = false
    private(set) var log: [String] = []

    private var stack: SipralStack?
    private var account: Account?
    private var call: Call?
    #if canImport(AVFoundation)
    private var audio: AudioBridge?
    #endif
    private var eventTask: Task<Void, Never>?
    private var callEventTask: Task<Void, Never>?

    func append(_ line: String) {
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }

    func start() {
        guard stack == nil else { return }
        do {
            let stack = try SipralStack()
            self.stack = stack
            append("listening on \(stack.bindAddress)")
            let events = stack.events()
            eventTask = Task { [weak self] in
                for await event in events {
                    await self?.handleStackEvent(event)
                }
            }
        } catch {
            status = .failed("\(error)")
        }
    }

    func register() {
        guard let stack else { return }
        do {
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
            let call = try stack.placeCall(account: account, target: target)
            attach(call)
        } catch {
            append("call failed: \(error)")
        }
    }

    func answer(_ event: SipralEvent) {
        guard let stack else { return }
        do {
            // Attached before it is answered, so that its reader is there
            // for the first event the answer brings.
            let call = try stack.takeIncomingCall(event)
            attach(call)
            try call.answer()
        } catch {
            append("answer failed: \(error)")
        }
    }

    func hangup() {
        try? call?.hangup()
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
        append(event.kindName)
        if event.kind == .registrationChanged {
            switch event.registrationData?.state {
            case .some(.registered): status = .registered
            case .some(.failed): status = .failed("registration failed")
            default: break
            }
        }
        if event.kind == .incomingCall {
            answer(event)
        }
    }

    private func handleCallEvent(_ event: SipralEvent, call: Call) async {
        callState = try? call.state
        if let data = event.callData {
            onHold = data.heldHere
        }
        if event.kind == .mediaStarted, let media = call.media {
            #if canImport(AVFoundation)
            let bridge = AudioBridge()
            audio = bridge
            try? bridge.start(for: media)
            #endif
        }
        if event.kind == .callEnded {
            #if canImport(AVFoundation)
            audio?.stop()
            audio = nil
            #endif
            self.call?.close()
            self.call = nil
            callState = nil
        }
    }
}
