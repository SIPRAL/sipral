// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import XCTest
@testable import Sipral

/// ABI 0.29's signalling surface through this package, between two stacks on
/// 127.0.0.1: why a call ended (RFC 3326) both ways, who is calling behind
/// the trust gate (RFC 3325, 3323, 5806, 7044), how the call asked to be
/// answered (RFC 5373, `Alert-Info`), a 3xx answer, the account's session
/// timer, and a call moved to a new socket after the network changed.
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
        // alice's confirmation says nothing about bob's end: his Media is made
        // when his own call hears it is confirmed, on his event thread
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
        XCTAssertNotEqual(pair.alice.bindAddress, oldSignalling, "the signalling socket stayed where it was")
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

    func testACallUnderNoChangeIsNotAskedToMove() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let address = stack.bindAddress
        let recovery = try stack.networkChanged(to: SipralStack.Network(link: .wired, address: "127.0.0.1"))
        XCTAssertEqual(recovery, .nothing)
        XCTAssertEqual(stack.bindAddress, address)
    }
}
