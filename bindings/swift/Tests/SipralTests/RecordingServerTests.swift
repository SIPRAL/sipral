// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Network)
import Dispatch
import Foundation
import Network
import XCTest
@testable import Sipral

/// A recording server (SIPREC, RFC 7866) on a TCP port of this machine's
/// loopback: it answers the recording session's INVITE with one
/// receive-only stream per party, on the two sockets it is given, and every
/// BYE with 200. Every request is kept.
final class FakeRecordingServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.sipral.test.recorder")
    private let lock = NSLock()
    private var _requests: [String] = []
    private var open: [NWConnection] = []
    private let streams: (UInt16, UInt16)
    let port: UInt16

    init(streams: (UInt16, UInt16)) throws {
        self.streams = streams
        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        var accepted: (NWConnection) -> Void = { _ in }
        listener.newConnectionHandler = { accepted($0) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, let bound = listener.port?.rawValue else {
            throw XCTSkip("the fake recording server could not listen")
        }
        port = bound
        accepted = { [weak self] connection in self?.serve(connection) }
    }

    var address: String { "127.0.0.1:\(port)" }

    var requests: [String] { lock.withLock { _requests } }

    func stop() {
        let all = lock.withLock { () -> [NWConnection] in
            defer { open = [] }
            return open
        }
        all.forEach { $0.cancel() }
        listener.cancel()
    }

    private func serve(_ connection: NWConnection) {
        lock.withLock { open.append(connection) }
        connection.start(queue: queue)
        read(connection, held: "")
    }

    private func read(_ connection: NWConnection, held: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var held = held + (data.map { String(decoding: $0, as: UTF8.self) } ?? "")
            while let end = held.range(of: "\r\n\r\n") {
                let head = String(held[..<end.lowerBound])
                let length = Int(FakePeer.header("Content-Length", in: head + "\r\n\r\n") ?? "0") ?? 0
                let body = held[end.upperBound...]
                guard body.utf8.count >= length else { break }
                let message = head + "\r\n\r\n" + String(body.prefix(length))
                held = String(body.dropFirst(length))
                self.lock.withLock { self._requests.append(message) }
                if let answer = self.answer(to: message) {
                    connection.send(content: Data(answer), completion: .idempotent)
                }
            }
            if complete || error != nil {
                connection.cancel()
                return
            }
            self.read(connection, held: held)
        }
    }

    private func answer(to message: String) -> [UInt8]? {
        if message.hasPrefix("INVITE ") {
            let sdp = "v=0\r\no=srs 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
                + "m=audio \(streams.0) RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=recvonly\r\n"
                + "m=audio \(streams.1) RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:2\r\na=recvonly\r\n"
            return FakePeer.answer(
                message, "200 OK", more: "Contact: <sip:srs@\(address);transport=tcp>\r\n",
                type: "application/sdp", body: sdp
            )
        }
        if message.hasPrefix("BYE ") {
            return FakePeer.answer(message, "200 OK")
        }
        return nil
    }
}

/// A call recorded to a recording server through `Call.record(toServer:)`:
/// the session's INVITE carries `Require: siprec` and the metadata, both
/// parties' audio reaches the server on a stream each, and stopping hangs
/// the session up.
final class RecordingServerTests: XCTestCase {
    /// How many RTP packets reached `socket` since the last time.
    private func counted(_ socket: UDPSocket) -> Int {
        var count = 0
        while let (data, _) = socket.receive() {
            if data.count > 12 && data[0] >> 6 == 2 {
                count += 1
            }
        }
        return count
    }

    func testACallIsRecordedToARecordingServerOverItsOwnConnection() async throws {
        let first = try UDPSocket(host: "127.0.0.1", port: 0)
        let second = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { first.close(); second.close() }
        let server = try FakeRecordingServer(
            streams: (UDPSocket.parse(first.localAddress).port, UDPSocket.parse(second.localAddress).port)
        )
        defer { server.stop() }

        let alice = try SipralStack(audio: .application, codecs: "PCMU")
        let bob = try SipralStack(audio: .application, codecs: "PCMU")
        defer { alice.close(); bob.close() }
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let aliceEvents = Recorder(alice.events())
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        defer { aliceCall.close() }
        XCTAssertThrowsError(try aliceCall.record(toServer: "sip:srs@127.0.0.1", destination: server.address)) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState, "no media yet")
        }
        let arrived = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let bobCall = try bob.answerCall(try XCTUnwrap(arrived, "no incoming call"))
        defer { bobCall.close() }
        let up = await eventually(within: 10) { aliceCall.media != nil && bobCall.media != nil }
        XCTAssertTrue(up, "media never started")

        let session = try aliceCall.record(toServer: "sip:srs@127.0.0.1", destination: server.address)
        XCTAssertNotEqual(session.handle, aliceCall.handle)
        XCTAssertTrue(aliceCall.recordingSession === session)
        let confirmed = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed && $0.call == session.handle }
        XCTAssertNotNil(confirmed, "the recording session never came up")
        let invite = try XCTUnwrap(server.requests.first { $0.hasPrefix("INVITE ") })
        XCTAssertTrue(invite.hasPrefix("INVITE sip:srs@127.0.0.1"), invite)
        XCTAssertEqual(FakePeer.header("Require", in: invite), "siprec")
        XCTAssertTrue(FakePeer.header("Content-Type", in: invite)?.hasPrefix("multipart/mixed") ?? false, invite)
        XCTAssertTrue(invite.contains("application/rs-metadata+xml"), invite)
        XCTAssertTrue(invite.contains("a=label:1") && invite.contains("a=label:2"), invite)
        XCTAssertTrue(invite.contains("m=audio \(UDPSocket.parse(session.thisEnd).port) "), invite)
        XCTAssertTrue(invite.contains("m=audio \(UDPSocket.parse(session.farEnd).port) "), invite)

        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)
        var (heardThisEnd, heardFarEnd) = (0, 0)
        let copied = await eventually(within: 5) {
            aliceMedia.sendAudio([Int16](repeating: 500, count: aliceMedia.frameSamples))
            bobMedia.sendAudio([Int16](repeating: 500, count: bobMedia.frameSamples))
            heardThisEnd += self.counted(first)
            heardFarEnd += self.counted(second)
            return heardThisEnd >= 10 && heardFarEnd >= 10
        }
        XCTAssertTrue(copied, "this end's copy: \(heardThisEnd), the far end's: \(heardFarEnd)")

        try session.stop()
        XCTAssertNil(aliceCall.recordingSession)
        let hungUp = await eventually(within: 5) { server.requests.contains { $0.hasPrefix("BYE ") } }
        XCTAssertTrue(hungUp, "the recording session was not hung up")
        let ended = await aliceEvents.first(within: 5) { $0.kind == .callEnded && $0.call == session.handle }
        XCTAssertNotNil(ended, "the recording session never ended")
        try await Task.sleep(nanoseconds: 200_000_000)
        _ = counted(first)
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(counted(first), 0, "copies went on after the recording stopped")
        XCTAssertThrowsError(try aliceCall.stopRecordingToServer()) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState, "nothing records the call now")
        }
    }

    /// The recording session's offer for a call keyed with SDES (RFC 4568),
    /// placed from an account that does or does not let its encrypted calls
    /// be recorded in the clear.
    private func recordingOfferOfAnEncryptedCall(recordingInClear: Bool) async throws -> String {
        let first = try UDPSocket(host: "127.0.0.1", port: 0)
        let second = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { first.close(); second.close() }
        let server = try FakeRecordingServer(
            streams: (UDPSocket.parse(first.localAddress).port, UDPSocket.parse(second.localAddress).port)
        )
        defer { server.stop() }

        let alice = try SipralStack(audio: .application, codecs: "PCMU")
        let bob = try SipralStack(audio: .application, codecs: "PCMU")
        defer { alice.close(); bob.close() }
        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress,
            security: AccountSecurity(srtp: .required, recordingInClear: recordingInClear)
        )
        _ = try bob.addAccount(
            aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress,
            security: AccountSecurity(srtp: .required)
        )
        let bobEvents = Recorder(bob.events())
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        defer { aliceCall.close() }
        let arrived = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let bobCall = try bob.answerCall(try XCTUnwrap(arrived, "no incoming call"))
        defer { bobCall.close() }
        let up = await eventually(within: 10) { aliceCall.media != nil && bobCall.media != nil }
        XCTAssertTrue(up, "media never started")
        XCTAssertEqual(try XCTUnwrap(aliceCall.media).encryption().first?.encrypted, true, "the call itself is keyed")

        _ = try aliceCall.record(toServer: "sip:srs@127.0.0.1", destination: server.address)
        let offered = await eventually(within: 5) { server.requests.contains { $0.hasPrefix("INVITE ") } }
        XCTAssertTrue(offered, "the recording session was never offered")
        return try XCTUnwrap(server.requests.first { $0.hasPrefix("INVITE ") })
    }

    func testAnEncryptedCallIsOfferedToItsRecorderAsSrtp() async throws {
        let offer = try await recordingOfferOfAnEncryptedCall(recordingInClear: false)
        XCTAssertEqual(offer.components(separatedBy: "RTP/SAVP").count - 1, 2, offer)
        XCTAssertTrue(offer.contains("a=crypto:"), offer)
    }

    func testAnAccountThatAllowsItRecordsAnEncryptedCallInTheClear() async throws {
        let offer = try await recordingOfferOfAnEncryptedCall(recordingInClear: true)
        XCTAssertEqual(offer.components(separatedBy: "RTP/AVP").count - 1, 2, offer)
        XCTAssertFalse(offer.contains("RTP/SAVP"), offer)
        XCTAssertFalse(offer.contains("a=crypto:"), offer)
    }
}
#endif
