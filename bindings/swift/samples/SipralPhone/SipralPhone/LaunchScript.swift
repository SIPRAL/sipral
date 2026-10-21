// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// A run driven from the launch environment instead of the screen, for the
/// simulator and the lab, where nobody taps: `xcrun simctl launch` hands
/// the application every `SIMCTL_CHILD_<NAME>` as `<NAME>`, and Xcode's
/// scheme editor does the same on a phone. Nothing given here is saved.
///
/// - `SIPRAL_PHONE_SERVER`, `_PORT`, `_TRANSPORT` (udp, tcp, tls), `_USER`,
///   `_AUTH_USER`, `_DOMAIN`, `_PASSWORD`, `_SRTP` (off, offered,
///   required), `_REGISTER=0` for a peer with no registrar: the account
///   for this run.
/// - `SIPRAL_PHONE_CALL`: what to dial once registered (or after five
///   seconds), `SIPRAL_PHONE_CALL_AFTER` seconds later (default none);
///   `SIPRAL_PHONE_CALL_SECONDS`: hang up that long after the call is
///   placed; `SIPRAL_PHONE_DTMF`: digits sent three seconds in.
/// - `SIPRAL_PHONE_ANSWER=1`: answer a call in the application's own
///   incoming screen at once.
/// - `SIPRAL_PHONE_EVIDENCE=1`: write the evidence file when a call ends;
///   `SIPRAL_PHONE_UNREGISTER=1`: unregister when it ends.
struct LaunchScript {
    let settings: PhoneSettings?
    let password: String?
    let call: String?
    let callAfter: Int
    let callSeconds: Int?
    let digits: String?
    let answers: Bool
    let evidence: Bool
    let unregisters: Bool

    init(environment: [String: String]) {
        func value(_ name: String) -> String? {
            environment["SIPRAL_PHONE_\(name)"].flatMap { $0.isEmpty ? nil : $0 }
        }
        if let server = value("SERVER"), let user = value("USER") {
            var settings = PhoneSettings()
            settings.server = server
            settings.user = user
            settings.port = value("PORT").flatMap(UInt16.init) ?? 5060
            settings.transport = value("TRANSPORT").flatMap(SignallingChoice.init(rawValue:)) ?? .udp
            settings.authUser = value("AUTH_USER") ?? ""
            settings.domain = value("DOMAIN") ?? ""
            settings.srtp = value("SRTP").flatMap(SrtpChoice.init(rawValue:)) ?? .off
            settings.registers = value("REGISTER") != "0"
            self.settings = settings
        } else {
            settings = nil
        }
        password = value("PASSWORD")
        call = value("CALL")
        callAfter = value("CALL_AFTER").flatMap(Int.init) ?? 0
        callSeconds = value("CALL_SECONDS").flatMap(Int.init)
        digits = value("DTMF")
        answers = value("ANSWER") == "1"
        evidence = value("EVIDENCE") == "1"
        unregisters = value("UNREGISTER") == "1"
    }

    @MainActor
    func run(on model: PhoneModel) {
        guard let call else { return }
        Task {
            for _ in 0..<100 {
                if case .registered = model.registration { break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            if callAfter > 0 {
                try? await Task.sleep(nanoseconds: UInt64(callAfter) * 1_000_000_000)
            }
            guard model.canDial else {
                model.log.note("scripted call to \(call) not placed: no account")
                return
            }
            model.dial(call)
        }
    }

    @MainActor
    func callEnded(on model: PhoneModel) {
        if evidence {
            _ = model.writeEvidence()
        }
        if unregisters {
            model.unregister()
        }
    }
}
