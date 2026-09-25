// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import XCTest
@testable import Sipral

/// One call from wherever this suite runs to a peer outside the process:
/// the iOS Simulator calling `SipralLabAgent` on the Mac that hosts it,
/// which is what it was written for. The agent answers, echoes every
/// frame back, and hangs up when it hears "#" -- so the call is set up,
/// carries audio both ways, and is ended by the far end's BYE.
///
/// Opt-in: it runs only when `SIPRAL_PEER` names the peer as `host:port`.
/// `xcodebuild` hands a test process every `TEST_RUNNER_<NAME>` variable
/// of its own environment as `<NAME>`, so
/// `TEST_RUNNER_SIPRAL_PEER=127.0.0.1:5070 xcodebuild test ...` reaches it
/// in the simulator, which shares the Mac's network stack.
/// `SIPRAL_LOCAL_HOST` is the address this end binds and advertises,
/// `127.0.0.1` unless the peer is somewhere loopback does not reach.
/// `docs/15-mobile.md`, "The Swift package on iOS", has the whole run.
final class HostPeerCallTests: XCTestCase {
    func testCallToThePeerNamedBySipralPeer() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let peer = environment["SIPRAL_PEER"], !peer.isEmpty else {
            throw XCTSkip(
                "SIPRAL_PEER is not set: this call needs a peer outside the process "
                    + "(SipralLabAgent, run on the host), named as host:port"
            )
        }
        let localHost = environment["SIPRAL_LOCAL_HOST"] ?? "127.0.0.1"

        let stack = try SipralStack(bindHost: localHost)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:caller@sipral.invalid", registrarAddress: peer)

        let placed = DispatchTime.now()
        let call = try stack.placeCall(account: account, target: "sip:agent@\(peer)", mediaHost: localHost)
        defer { call.close() }
        let events = Recorder(call.events)

        let confirmed = await events.first(within: 10) { $0.kind == .callConfirmed }
        let setupMs = (DispatchTime.now().uptimeNanoseconds - placed.uptimeNanoseconds) / 1_000_000
        XCTAssertNotNil(confirmed, "the peer at \(peer) never answered")
        guard confirmed != nil else { return }
        let state = try call.state
        XCTAssertEqual(state, .confirmed)
        print("host-peer call: confirmed in \(setupMs) ms")

        let started = await events.first(within: 5) { $0.kind == .mediaStarted }
        let media = try XCTUnwrap(started.flatMap { _ in call.media }, "media never started")
        let frames = Recorder(media.frames)

        // One second of a square wave at a quarter of full scale: loud
        // enough that the echo is told apart from the silence and comfort
        // noise the agent sends when it has nothing to echo.
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

        try call.sendDtmf("#")
        let ended = await events.first(within: 10) { $0.kind == .callEnded }
        XCTAssertEqual(ended?.callData?.endReason, .remoteHangup, "the peer did not hang up on #")
        print("host-peer call: ended by the peer, \(String(describing: ended?.callData?.endReason))")
    }
}
