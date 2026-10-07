// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import XCTest
@testable import Sipral

/// Two stacks on 127.0.0.1: `Reason` (RFC 3326), caller identity (RFC 3325,
/// 3323, 5806, 7044), answer mode (RFC 5373), 3xx, session timer, and a
/// call moved after a network change.
final class SignallingSurfaceTests: XCTestCase {
    private struct Pair {
        let alice: SipralStack
        let bob: SipralStack
        let aliceAccount: Account
        let bobEvents: Recorder<SipralEvent>

        func close() {
            alice.close()
            bob.close()
        }
    }

    private func pair(
        alicePrivacy: Privacy = [], aliceTrusts: [String] = [], bobTrusts: [String] = [], srtp: SipralSrtp? = nil
    ) throws -> Pair {
        let alice = try SipralStack(audio: .application, srtp: srtp)
        let bob = try SipralStack(audio: .application, srtp: srtp)
        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress,
            privacy: alicePrivacy, trustedPeers: aliceTrusts
        )
        _ = try bob.addAccount(
            aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress, trustedPeers: bobTrusts
        )
        return Pair(alice: alice, bob: bob, aliceAccount: aliceAccount, bobEvents: Recorder(bob.events()))
    }

    private func incoming(_ pair: Pair) async throws -> SipralEvent {
        let arrived = await pair.bobEvents.first(within: 5) { $0.kind == .incomingCall }
        return try XCTUnwrap(arrived, "no call came in")
    }

    private func confirmed(_ call: Call, _ events: Recorder<SipralEvent>) async throws {
        let up = await events.first(within: 5) { $0.kind == .mediaStarted || $0.kind == .callEnded }
        XCTAssertEqual(up?.kind, .mediaStarted, "the call never got media")
        let minted = await eventually(within: 5) { call.media != nil }
        XCTAssertTrue(minted)
    }

    private func endOf(_ events: Recorder<SipralEvent>) async throws -> SipralEvent {
        let ended = await events.first(within: 5) { $0.kind == .callEnded }
        return try XCTUnwrap(ended, "the call never ended")
    }

    // MARK: - Reason

    func testAHangupWithAReasonReachesTheFarEndsEndedEvent() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        let aliceEvents = Recorder(placed.events())
        let taken = try pair.bob.takeIncomingCall(try await incoming(pair))
        let bobEvents = Recorder(taken.events())
        try taken.answer()
        try await confirmed(placed, aliceEvents)
        defer { placed.close(); taken.close() }

        try placed.hangup(reason: .userBusy)
        let ended = try await endOf(bobEvents)
        XCTAssertEqual(ended.callData?.endCause, EndCause(sip: nil, q850: 17, text: nil))
    }

    func testACallCancelledAsCompletedElsewhereIsNoMissedCall() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        defer { placed.close() }
        let ringing = try await incoming(pair)
        let taken = try pair.bob.takeIncomingCall(ringing)
        defer { taken.close() }
        let bobEvents = Recorder(taken.events())

        try placed.hangup(reason: .completedElsewhere)
        let ended = try await endOf(bobEvents)
        let cause = try XCTUnwrap(ended.callData?.endCause, "the CANCEL carried no Reason")
        XCTAssertTrue(cause.completedElsewhere)
        XCTAssertEqual(cause.text, "Call completed elsewhere")
    }

    // MARK: - 3xx

    func testARingingCallIsSentElsewhereWithA302() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        defer { placed.close() }
        let aliceEvents = Recorder(placed.events())
        let ringing = try await incoming(pair)

        XCTAssertThrowsError(try pair.bob.redirectCall(ringing, to: ["sip:carol@sipral.invalid"], status: 486)) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
        try pair.bob.redirectCall(
            ringing, to: ["sip:carol@sipral.invalid", "sip:dave@sipral.invalid"], reason: "unconditional"
        )
        let ended = try await endOf(aliceEvents)
        XCTAssertEqual(ended.callData?.statusCode, 302)
    }

    func testACallPlacedToFollowRedirectsGoesOnToTheTargetA302Names() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(
            account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)", followRedirects: true
        )
        defer { placed.close() }
        let aliceEvents = Recorder(placed.events())
        let ringing = try await incoming(pair)

        try pair.bob.redirectCall(ringing, to: ["sip:carol@\(pair.bob.bindAddress)"])
        let rungAgain = await pair.bobEvents.count(atLeast: 2, within: 5) { $0.kind == .incomingCall }
        XCTAssertEqual(rungAgain, 2, "the INVITE did not go on to the target the 302 named")
        XCTAssertNil(
            aliceEvents.elements.first { $0.kind == .callEnded },
            "the call ended at the redirect"
        )
    }

    // MARK: - who is calling, and how to answer

    func testACallersAssertedIdentityIsReadOnlyFromATrustedPeer() async throws {
        let headers = [
            SipralHeader(name: "P-Asserted-Identity", value: "\"Front Desk\" <sip:1000@sipral.invalid>"),
            SipralHeader(name: "Diversion", value: "<sip:dave@sipral.invalid>;reason=unconditional;counter=1"),
            SipralHeader(
                name: "History-Info",
                value: "<sip:bob@sipral.invalid>;index=1, <sip:carol@sipral.invalid>;index=1.1"
            ),
        ]
        for trusted in [true, false] {
            let pair = try pair(bobTrusts: trusted ? ["127.0.0.1"] : [])
            defer { pair.close() }
            let placed = try pair.alice.placeCall(
                account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)", headers: headers
            )
            defer { placed.close() }
            let ringing = try await incoming(pair)
            let identity = try pair.bob.callerIdentity(of: ringing)

            XCTAssertEqual(identity.trusted, trusted)
            XCTAssertEqual(ringing.callData?.identityTrusted, trusted)
            if trusted {
                XCTAssertEqual(identity.asserted, Party(uri: "sip:1000@sipral.invalid", displayName: "Front Desk"))
                XCTAssertEqual(identity.assertedParties.map(\.uri), ["sip:1000@sipral.invalid"])
            } else {
                XCTAssertNil(identity.asserted, "an untrusted peer's assertion is believed")
                XCTAssertEqual(identity.verstat, .none)
            }
            XCTAssertEqual(
                identity.diversions,
                [Diversion(uri: "sip:dave@sipral.invalid", displayName: nil, reason: "unconditional")]
            )
            XCTAssertEqual(ringing.callData?.diversionCount, 1)
            XCTAssertEqual(identity.history.map(\.uri), ["sip:bob@sipral.invalid", "sip:carol@sipral.invalid"])
            XCTAssertEqual(identity.history.map(\.index), ["1", "1.1"])

            let taken = try pair.bob.takeIncomingCall(ringing)
            XCTAssertEqual(try taken.identity(), identity, "the call reads what its event did")
            taken.close()
        }
    }

    func testAnAnonymousAccountWithholdsItsNumberAndAssertsItOnlyToATrustedPeer() async throws {
        let pair = try pair(alicePrivacy: [.id], aliceTrusts: ["127.0.0.1"], bobTrusts: ["127.0.0.1"])
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        defer { placed.close() }
        let ringing = try await incoming(pair)

        XCTAssertEqual(ringing.callData?.fromUri, "sip:anonymous@anonymous.invalid")
        XCTAssertTrue(ringing.callData?.privacy.contains(.id) ?? false)
        let identity = try pair.bob.callerIdentity(of: ringing)
        XCTAssertEqual(identity.asserted?.uri, "sip:alice@sipral.invalid")
        XCTAssertTrue(identity.privacy.contains(.id))
    }

    func testHowACallAskedToBeAnsweredAndRung() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(
            account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)",
            headers: [
                SipralHeader(name: "Answer-Mode", value: "Auto;require"),
                SipralHeader(name: "Alert-Info", value: "<urn:alert:source:external>"),
            ]
        )
        defer { placed.close() }
        let ringing = try await incoming(pair)
        let answering = try pair.bob.answering(of: ringing)

        XCTAssertEqual(answering.mode, .auto)
        XCTAssertTrue(answering.modeRequired)
        XCTAssertNotNil(answering.answerAfterMs, "Answer-Mode: Auto asks to be answered without the person")
        XCTAssertEqual(answering.ringSource, .external)
        XCTAssertEqual(answering.alertInfo.map(\.uri), ["urn:alert:source:external"])
    }

    // MARK: - SRTP

    func testTheSuiteASecuredCallRunsHasAName() async throws {
        let pair = try pair(srtp: .dtlsRequired)
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        let aliceEvents = Recorder(placed.events())
        let taken = try pair.bob.takeIncomingCall(try await incoming(pair))
        defer { placed.close(); taken.close() }
        try taken.answer()

        let secured = await aliceEvents.first(within: 5) { $0.kind == .mediaSecured }
        let suite = try XCTUnwrap(secured?.mediaData?.srtpSuite, "no suite, or one this package has no name for")
        XCTAssertNotEqual(suite, .unknown)
    }

    // MARK: - the account's options

    func testASessionTimerBelowTheFloorIsRefusedAndOneAboveItIsAsked() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertThrowsError(
            try stack.addAccount(
                aor: "sip:alice@sipral.invalid", registrarAddress: "127.0.0.1:5060",
                sessionTimer: .interval(seconds: 30)
            )
        ) { XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument) }

        let pair = try pair()
        defer { pair.close() }
        let timed = try pair.alice.addAccount(
            aor: "sip:timed@sipral.invalid", registrarAddress: pair.bob.bindAddress,
            sessionTimer: .interval(seconds: 120)
        )
        let placed = try pair.alice.placeCall(account: timed, target: "sip:bob@\(pair.bob.bindAddress)")
        defer { placed.close() }
        let ringing = try await incoming(pair)
        let invite = String(decoding: ringing.message ?? [], as: UTF8.self)
        XCTAssertTrue(invite.contains("Session-Expires: 120"), "the INVITE asked for no 120 s timer:\n\(invite)")
    }

    // MARK: - the network changing under a call

    func testACallMovedAfterTheNetworkChangedIsHeardAtItsNewSocket() async throws {
        let pair = try pair()
        defer { pair.close() }
        let placed = try pair.alice.placeCall(account: pair.aliceAccount, target: "sip:bob@\(pair.bob.bindAddress)")
        let aliceEvents = Recorder(placed.events())
        let taken = try pair.bob.takeIncomingCall(try await incoming(pair))
        try taken.answer()
        try await confirmed(placed, aliceEvents)
        defer { placed.close(); taken.close() }
        // bob's Media appears on his own confirmation, not alice's
        let minted = await eventually(within: 5) { placed.media != nil && taken.media != nil }
        XCTAssertTrue(minted, "a confirmed call has no Media at one end")
        let aliceMedia = try XCTUnwrap(placed.media)
        let bobMedia = try XCTUnwrap(taken.media)
        let flowing = await eventually(within: 5) { bobMedia.remoteAddress != nil }
        XCTAssertTrue(flowing)

        let oldSignalling = pair.alice.bindAddress
        let oldMedia = aliceMedia.localAddress
        let recovery = try pair.alice.networkChanged(
            to: SipralStack.Network(link: .wired, address: "127.0.0.1", interface: "moved")
        )
        XCTAssertEqual(recovery, .rebuild)
        XCTAssertEqual(pair.alice.bindAddress, oldSignalling, "the address and the port did not change, so neither did the socket's")
        XCTAssertTrue(pair.alice.keptSignallingPort)
        XCTAssertTrue(pair.aliceAccount.contact.contains(pair.alice.bindAddress))

        let wanted = await aliceEvents.first(within: 5) { $0.kind == .callAddressWanted }
        XCTAssertEqual(wanted?.call, placed.handle)
        let changes = aliceEvents.elements.count
        try placed.moveMedia()
        XCTAssertNotEqual(aliceMedia.localAddress, oldMedia)
        let answered = await aliceEvents.first(within: 5, after: changes) {
            $0.kind == .sessionChanged || $0.kind == .sessionChangeFailed
        }
        XCTAssertEqual(answered?.kind, .sessionChanged)

        let before = try aliceMedia.statistics().packets_received
        let heard = await eventually(within: 3) {
            ((try? aliceMedia.statistics().packets_received) ?? 0) > before + 10
        }
        XCTAssertTrue(heard, "the far end kept sending to the socket the call left")
    }

    /// The address the route to the rest of the world leaves from, when the
    /// machine has one beside loopback.
    private func otherAddress() throws -> String {
        let host = SipralStack.routeHost(toward: "192.0.2.1:5060")
        guard host != "127.0.0.1" else { throw XCTSkip("this machine has no address but loopback") }
        return host
    }

    /// A free UDP port at `host`, found by binding one and letting it go.
    private func freePort(at host: String) throws -> UInt16 {
        let probe = try UDPSocket(host: host, port: 0)
        defer { probe.close() }
        return UDPSocket.parse(probe.localAddress).port
    }

    /// The port the application chose survives a move to another address,
    /// and with none chosen the port in use does.
    func testTheSignallingPortSurvivesAMoveToAnotherAddress() throws {
        let elsewhere = try otherAddress()
        let chosen = try freePort(at: elsewhere)
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1", bindPort: chosen)
        defer { stack.close() }
        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: elsewhere, interface: "moved"))
        XCTAssertEqual(stack.bindAddress, "\(elsewhere):\(chosen)")
        XCTAssertTrue(stack.keptSignallingPort)
        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: "127.0.0.1", interface: "back"))
        XCTAssertEqual(stack.bindAddress, "127.0.0.1:\(chosen)")

        let picked = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { picked.close() }
        let port = UDPSocket.parse(picked.bindAddress).port
        try picked.networkChanged(to: SipralStack.Network(link: .wired, address: "127.0.0.1", interface: "moved"))
        XCTAssertEqual(picked.bindAddress, "127.0.0.1:\(port)")
        XCTAssertTrue(picked.keptSignallingPort)
    }

    /// A port another socket holds at the new address is not fought over:
    /// the system picks one, and the stack says so.
    func testAPortTakenAtTheNewAddressFallsBackAndSaysSo() throws {
        let elsewhere = try otherAddress()
        let squatter = try UDPSocket(host: elsewhere, port: 0)
        defer { squatter.close() }
        let taken = UDPSocket.parse(squatter.localAddress).port
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1", bindPort: taken)
        defer { stack.close() }
        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: elsewhere, interface: "moved"))
        let now = UDPSocket.parse(stack.bindAddress)
        XCTAssertEqual(now.host, elsewhere)
        XCTAssertNotEqual(now.port, taken)
        XCTAssertNotEqual(now.port, 0)
        XCTAssertFalse(stack.keptSignallingPort)
    }

    /// A move to an address this machine lacks fails with the signalling
    /// socket it had still open, so the next move keeps its port.
    func testAMoveToAnAddressThisMachineLacksKeepsTheSocketItHad() throws {
        let elsewhere = try otherAddress()
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let before = stack.bindAddress
        let port = UDPSocket.parse(before).port
        // TEST-NET-1 (RFC 5737): on no interface of this machine
        XCTAssertThrowsError(
            try stack.networkChanged(to: SipralStack.Network(link: .wired, address: "192.0.2.77", interface: "gone"))
        )
        XCTAssertEqual(stack.bindAddress, before)
        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: elsewhere, interface: "moved"))
        XCTAssertEqual(stack.bindAddress, "\(elsewhere):\(port)")
        XCTAssertTrue(stack.keptSignallingPort)
    }

    /// A wildcard-bound stack keeps its socket across a move and advertises
    /// the route toward each server, not the platform's address.
    func testAStackOnEveryInterfaceKeepsChoosingItsRouteAcrossAMove() throws {
        let elsewhere = try otherAddress()
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let port = UDPSocket.parse(stack.bindAddress).port
        let away = try stack.addAccount(aor: "sip:alice@192.0.2.1", registrarAddress: "192.0.2.1:5060")
        XCTAssertEqual(stack.bindAddress, "\(elsewhere):\(port)")

        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: elsewhere, interface: "moved"))
        let here = try stack.addAccount(aor: "sip:bob@127.0.0.1", registrarAddress: "127.0.0.1:5060")
        XCTAssertTrue(
            here.contact.contains("127.0.0.1:\(port)"),
            "an account added after the move is reached at the route toward its server: \(here.contact)"
        )

        try stack.networkChanged(to: SipralStack.Network(link: .wired, address: "127.0.0.1", interface: "back"))
        XCTAssertEqual(
            stack.bindAddress, "\(elsewhere):\(port)",
            "the route toward the first account's server, not the address the platform named"
        )
        XCTAssertTrue(stack.keptSignallingPort)
        XCTAssertTrue(away.contact.contains("\(elsewhere):\(port)"), away.contact)
        XCTAssertTrue(here.contact.contains("127.0.0.1:\(port)"), here.contact)
    }

    func testACallUnderNoChangeIsNotAskedToMove() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let address = stack.bindAddress
        let recovery = try stack.networkChanged(to: SipralStack.Network(link: .wired, address: "127.0.0.1"))
        XCTAssertEqual(recovery, .nothing)
        XCTAssertEqual(stack.bindAddress, address)
    }
}
