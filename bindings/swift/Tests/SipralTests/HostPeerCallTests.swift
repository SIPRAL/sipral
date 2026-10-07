// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import XCTest
@testable import Sipral

/// Calls to a peer outside the process, e.g. the iOS Simulator calling
/// `SipralLabAgent` on its host Mac, or through a registrar.
///
/// Runs only when `SIPRAL_PEER` (`host:port`) is set; under `xcodebuild`
/// pass it as `TEST_RUNNER_SIPRAL_PEER`.
///
/// - `SIPRAL_LOCAL_HOST` is the address this end binds and advertises,
///   `127.0.0.1` unless the peer is somewhere loopback does not reach.
/// - `SIPRAL_REGISTRAR` is a registrar URI. With it, the account registers
///   before anything else, as `SIPRAL_AOR` (`sip:caller@sipral.invalid`
///   otherwise), with `SIPRAL_AUTH_USER` and `SIPRAL_AUTH_PASSWORD` for the
///   registrar's challenge.
/// - `SIPRAL_TARGET` is the URI to call, `sip:agent@<SIPRAL_PEER>` unless
///   set. The agent hangs up when it hears "#"; any other target is hung up
///   by this end once the echo has been heard.
/// - `SIPRAL_WAIT_INCOMING_SECONDS`, with `SIPRAL_REGISTRAR`, turns on the
///   other direction: the account registers and waits that long for a call
///   through the registrar, answers it, and hangs it up once its audio has
///   come back.
///
/// `docs/15-mobile.md`, "The Swift package on iOS", has the runs.
final class HostPeerCallTests: XCTestCase {
    private struct Setup {
        let peer: String
        let localHost: String
        let registrar: String?
        let aor: String
        let authUser: String?
        let authPassword: String?

        init(_ environment: [String: String]) throws {
            guard let peer = environment["SIPRAL_PEER"], !peer.isEmpty else {
                throw XCTSkip(
                    "SIPRAL_PEER is not set: this call needs a peer outside the process "
                        + "(SipralLabAgent run on the host, or a registrar), named as host:port"
                )
            }
            self.peer = peer
            localHost = environment["SIPRAL_LOCAL_HOST"] ?? "127.0.0.1"
            registrar = environment["SIPRAL_REGISTRAR"].flatMap { $0.isEmpty ? nil : $0 }
            aor = environment["SIPRAL_AOR"] ?? "sip:caller@sipral.invalid"
            authUser = environment["SIPRAL_AUTH_USER"]
            authPassword = environment["SIPRAL_AUTH_PASSWORD"]
        }

        /// The account (registered first when there is a registrar) and the
        /// stack's event stream.
        func account(on stack: SipralStack, stackEvents: Recorder<SipralEvent>) async throws -> Account {
            let account = try stack.addAccount(
                aor: aor,
                registrarAddress: peer,
                registrar: registrar,
                authUser: authUser,
                authPassword: authPassword
            )
            guard let registrar else { return account }
            let asked = DispatchTime.now()
            try account.register()
            let answered = await stackEvents.first(within: 10) { event in
                guard event.kind == .registrationChanged, let state = event.registrationData?.state else {
                    return false
                }
                return state == .registered || state == .failed || state == .retrying
            }
            let registerMs = (DispatchTime.now().uptimeNanoseconds - asked.uptimeNanoseconds) / 1_000_000
            let registration = try XCTUnwrap(answered?.registrationData, "\(registrar) never answered the REGISTER")
            XCTAssertEqual(
                registration.state, .registered,
                "\(registrar) did not register \(aor): status \(registration.statusCode)"
            )
            print("host-peer call: registered \(aor) at \(registrar) in \(registerMs) ms")
            return account
        }
    }

    func testCallToThePeerNamedBySipralPeer() async throws {
        let environment = ProcessInfo.processInfo.environment
        let setup = try Setup(environment)
        let target = environment["SIPRAL_TARGET"].flatMap { $0.isEmpty ? nil : $0 }

        let stack = try SipralStack(audio: .application, bindHost: setup.localHost)
        defer { stack.close() }
        let stackEvents = Recorder(stack.events())
        let account = try await setup.account(on: stack, stackEvents: stackEvents)

        let placed = DispatchTime.now()
        let call = try stack.placeCall(
            account: account, target: target ?? "sip:agent@\(setup.peer)", mediaHost: setup.localHost
        )
        defer { call.close() }
        let events = Recorder(call.events())

        let confirmed = await events.first(within: 10) { $0.kind == .callConfirmed }
        let setupMs = (DispatchTime.now().uptimeNanoseconds - placed.uptimeNanoseconds) / 1_000_000
        XCTAssertNotNil(confirmed, "the peer at \(setup.peer) never answered")
        guard confirmed != nil else { return }
        let state = try call.state
        XCTAssertEqual(state, .confirmed)
        print("host-peer call: confirmed in \(setupMs) ms")

        try await exchangeAudio(on: call, events: events)

        if target == nil {
            try call.sendDtmf("#")
            let ended = await events.first(within: 10) { $0.kind == .callEnded }
            XCTAssertEqual(ended?.callData?.endReason, .remoteHangup, "the peer did not hang up on #")
            print("host-peer call: ended by the peer, \(String(describing: ended?.callData?.endReason))")
        } else {
            try call.hangup()
            let ended = await events.first(within: 10) { $0.kind == .callEnded }
            XCTAssertEqual(ended?.callData?.endReason, .localHangup, "the hang-up was not acknowledged")
            print("host-peer call: ended by this end, \(String(describing: ended?.callData?.endReason))")
        }
    }

    func testCallFromThePeerThroughTheRegistrar() async throws {
        let environment = ProcessInfo.processInfo.environment
        let setup = try Setup(environment)
        guard setup.registrar != nil,
            let wait = environment["SIPRAL_WAIT_INCOMING_SECONDS"].flatMap(Double.init), wait > 0
        else {
            throw XCTSkip(
                "an incoming call needs SIPRAL_REGISTRAR to be reached through, and "
                    + "SIPRAL_WAIT_INCOMING_SECONDS to say how long to wait for it"
            )
        }

        let stack = try SipralStack(audio: .application, bindHost: setup.localHost)
        defer { stack.close() }
        let stackEvents = Recorder(stack.events())
        _ = try await setup.account(on: stack, stackEvents: stackEvents)
        print("host-peer call: waiting \(Int(wait)) s for a call to \(setup.aor)")

        let incoming = await stackEvents.first(within: wait) { $0.kind == .incomingCall }
        let offered = try XCTUnwrap(incoming, "no call arrived within \(Int(wait)) s")
        let arrived = DispatchTime.now()
        let call = try stack.takeIncomingCall(offered, mediaHost: setup.localHost)
        defer { call.close() }
        let events = Recorder(call.events())
        try call.answer()

        let confirmed = await events.first(within: 10) { $0.kind == .callConfirmed }
        let answerMs = (DispatchTime.now().uptimeNanoseconds - arrived.uptimeNanoseconds) / 1_000_000
        XCTAssertNotNil(confirmed, "the caller never acknowledged the answer")
        guard confirmed != nil else { return }
        print("host-peer call: incoming call confirmed \(answerMs) ms after it arrived")

        try await exchangeAudio(on: call, events: events)

        try call.hangup()
        let ended = await events.first(within: 10) { $0.kind == .callEnded }
        XCTAssertEqual(ended?.callData?.endReason, .localHangup, "the hang-up was not acknowledged")
        print("host-peer call: incoming call ended by this end, \(String(describing: ended?.callData?.endReason))")
    }

    /// One second of square wave, loud enough to tell its echo from comfort
    /// noise.
    private func exchangeAudio(on call: Call, events: Recorder<SipralEvent>) async throws {
        let started = await events.first(within: 5) { $0.kind == .mediaStarted }
        let media = try XCTUnwrap(started.flatMap { _ in call.media }, "media never started")
        let frames = Recorder(media.frames())

        let period = 16
        let tone = (0..<(media.sampleRate)).map { index -> Int16 in
            (index / (period / 2)) % 2 == 0 ? 8192 : -8192
        }
        media.sendAudio(tone)
        let loud = await frames.count(atLeast: 25, within: 5) { frame in
            frame.contains { abs(Int32($0)) > 2048 }
        }
        XCTAssertGreaterThanOrEqual(loud, 25, "the tone did not come back from the peer")

        let stats = try media.statistics()
        print(
            "host-peer call: rtp packets_sent=\(stats.packets_sent) packets_received=\(stats.packets_received) "
                + "packets_lost=\(stats.packets_lost) echoed_frames=\(loud)"
        )
        XCTAssertGreaterThan(stats.packets_sent, 0)
        XCTAssertGreaterThan(stats.packets_received, 0)
    }
}
