// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif
import Dispatch
import Foundation
import XCTest
@testable import Sipral

/// A STUN and TURN server in the test itself, on 127.0.0.1, that tells every
/// socket it hears from that it appears at `203.0.113.7` (RFC 5737's
/// documentation range) on its own port plus ten thousand -- a NAT that
/// moves both the address and the port, so a `Contact` or an SDP naming the
/// socket's own address cannot pass for right.
///
/// Binding requests get an XOR-MAPPED-ADDRESS (RFC 8489 §14.2). An Allocate
/// (RFC 8656 §7) without a credential gets the 401 with a REALM and a NONCE
/// that makes a client sign the next one; a signed one is checked against
/// the long-term key -- MD5 of `username:realm:password` (RFC 8489 §9.2.2) --
/// and answered with a relay on `198.51.100.9`, signed the same way. Nothing
/// is answered until `open` is set, so a test takes its event stream before
/// the first answer can raise an event: the stack retransmits what was not
/// answered.
final class FakeStunServer: @unchecked Sendable {
    struct Request {
        let method: UInt16
        let from: String
        let bytes: [UInt8]
        let attributes: [UInt16: [UInt8]]
    }

    static let realm = "sipral.test"
    static let nonce = "0123456789abcdef"
    static let relayHost = "198.51.100.9"

    let socket: UDPSocket
    var address: String { socket.localAddress }
    private let credential: (username: String, password: String)?
    private let lock = NSLock()
    private var _open = false
    private var _requests: [Request] = []
    private var _signedAllocateVerified: Bool?
    private var running = true
    private let stopped = DispatchSemaphore(value: 0)

    /// The address every socket is told it appears at. A test in which
    /// something is later sent to a mapped address names one of this
    /// machine's own, so nothing leaves it.
    let publicHost: String

    init(
        host: String = "127.0.0.1", publicHost: String = "203.0.113.7",
        credential: (username: String, password: String)? = nil
    ) throws {
        socket = try UDPSocket(host: host, port: 0)
        self.publicHost = publicHost
        self.credential = credential
        DispatchQueue.global().async { [self] in serve() }
    }

    var open: Bool {
        get { lock.withLock { _open } }
        set { lock.withLock { _open = newValue } }
    }

    var requests: [Request] { lock.withLock { _requests } }

    /// Whether the MESSAGE-INTEGRITY of the signed Allocate checked out
    /// against the long-term key, or `nil` before one arrived.
    var signedAllocateVerified: Bool? { lock.withLock { _signedAllocateVerified } }

    func stop() {
        lock.withLock { running = false }
        _ = stopped.wait(timeout: .now() + 2)
        socket.close()
    }

    /// The address this server tells `local` it appears from.
    static func mapped(_ local: String, publicHost: String = "203.0.113.7") -> String {
        "\(publicHost):\(moved(UDPSocket.parse(local).port, by: 10000))"
    }

    /// A port twenty thousand away, or ten -- never the port itself.
    static func moved(_ port: UInt16, by distance: Int) -> Int {
        Int(port) > 40000 ? Int(port) - distance : Int(port) + distance
    }

    private func serve() {
        while lock.withLock({ running }) {
            var pfd = pollfd(fd: socket.fd, events: Int16(POLLIN), revents: 0)
            _ = poll(&pfd, 1, 20)
            while let (data, from) = socket.receive(capacity: 2048) {
                guard data.count >= 20, let request = Self.parse(data, from: from) else { continue }
                lock.withLock { _requests.append(request) }
                guard open, let answer = answer(request) else { continue }
                socket.send(answer, to: from)
            }
        }
        stopped.signal()
    }

    private func answer(_ request: Request) -> [UInt8]? {
        let transaction = Array(request.bytes[8..<20])
        switch request.method {
        case 0x0001:
            return Self.message(0x0101, transaction, [
                (0x0020, Self.xorAddress(Self.mapped(request.from, publicHost: publicHost))),
            ])
        case 0x0003:
            guard let credential else { return nil }
            guard let username = request.attributes[0x0006] else {
                return Self.message(0x0113, transaction, [
                    (0x0009, [0, 0, 4, 1] + Array("Unauthorized".utf8)),
                    (0x0014, Array(Self.realm.utf8)),
                    (0x0015, Array(Self.nonce.utf8)),
                ])
            }
            let key = Self.longTermKey(credential.username, credential.password)
            let verified = String(decoding: username, as: UTF8.self) == credential.username
                && Self.integrityHolds(request.bytes, key: key)
            lock.withLock { _signedAllocateVerified = verified }
            guard let key, verified else {
                return Self.message(0x0113, transaction, [(0x0009, [0, 0, 4, 1] + Array("Unauthorized".utf8))])
            }
            let (_, port) = UDPSocket.parse(request.from)
            return Self.signed(0x0103, transaction, [
                (0x0016, Self.xorAddress("\(Self.relayHost):\(Self.moved(port, by: 20000))")),
                (0x0020, Self.xorAddress(Self.mapped(request.from, publicHost: publicHost))),
                (0x000D, [0, 0, 0x02, 0x58]),
            ], key: key)
        default:
            return nil
        }
    }

    // MARK: - the wire format, RFC 8489 §5 and §14

    static let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]

    static func parse(_ data: [UInt8], from: String) -> Request? {
        guard Array(data[4..<8]) == cookie else { return nil }
        let type = UInt16(data[0]) << 8 | UInt16(data[1])
        guard type & 0x0110 == 0 else { return nil }
        let method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
        var attributes: [UInt16: [UInt8]] = [:]
        var offset = 20
        while offset + 4 <= data.count {
            let attribute = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            let length = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
            guard offset + 4 + length <= data.count else { break }
            attributes[attribute] = Array(data[(offset + 4)..<(offset + 4 + length)])
            offset += 4 + (length + 3) / 4 * 4
        }
        return Request(method: method, from: from, bytes: data, attributes: attributes)
    }

    static func message(_ type: UInt16, _ transaction: [UInt8], _ attributes: [(UInt16, [UInt8])]) -> [UInt8] {
        var body: [UInt8] = []
        for (attribute, value) in attributes {
            body += [UInt8(attribute >> 8), UInt8(attribute & 0xFF), UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
            body += value + [UInt8](repeating: 0, count: (4 - value.count % 4) % 4)
        }
        return [UInt8(type >> 8), UInt8(type & 0xFF), UInt8(body.count >> 8), UInt8(body.count & 0xFF)]
            + cookie + transaction + body
    }

    static func xorAddress(_ address: String) -> [UInt8] {
        let (host, port) = UDPSocket.parse(address)
        let octets = host.split(separator: ".").compactMap { UInt8($0) }
        let xport = port ^ 0x2112
        return [0, 0x01, UInt8(xport >> 8), UInt8(xport & 0xFF)] + zip(octets, cookie).map { $0 ^ $1 }
    }

    static func unxorAddress(_ value: [UInt8]) -> String {
        let port = (UInt16(value[2]) << 8 | UInt16(value[3])) ^ 0x2112
        let host = zip(value[4..<8], cookie).map { String($0 ^ $1) }.joined(separator: ".")
        return "\(host):\(port)"
    }

    #if canImport(CryptoKit)
    static func longTermKey(_ username: String, _ password: String) -> [UInt8]? {
        Array(Insecure.MD5.hash(data: Array("\(username):\(realm):\(password)".utf8)))
    }

    static func hmac(_ data: [UInt8], key: [UInt8]) -> [UInt8] {
        Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }
    #else
    static func longTermKey(_ username: String, _ password: String) -> [UInt8]? { nil }

    static func hmac(_ data: [UInt8], key: [UInt8]) -> [UInt8] { [] }
    #endif

    /// RFC 8489 §14.5: the HMAC covers the message up to the attribute,
    /// with the header's length counting up to the attribute's end.
    static func integrityHolds(_ message: [UInt8], key: [UInt8]?) -> Bool {
        guard let key else { return false }
        var offset = 20
        while offset + 4 <= message.count {
            let attribute = UInt16(message[offset]) << 8 | UInt16(message[offset + 1])
            let length = Int(message[offset + 2]) << 8 | Int(message[offset + 3])
            if attribute == 0x0008, length == 20, offset + 24 <= message.count {
                var covered = Array(message[0..<offset])
                let counted = offset + 24 - 20
                covered[2] = UInt8(counted >> 8)
                covered[3] = UInt8(counted & 0xFF)
                return hmac(covered, key: key) == Array(message[(offset + 4)..<(offset + 24)])
            }
            offset += 4 + (length + 3) / 4 * 4
        }
        return false
    }

    static func signed(
        _ type: UInt16, _ transaction: [UInt8], _ attributes: [(UInt16, [UInt8])], key: [UInt8]
    ) -> [UInt8] {
        var unsigned = message(type, transaction, attributes)
        let counted = unsigned.count - 20 + 24
        unsigned[2] = UInt8(counted >> 8)
        unsigned[3] = UInt8(counted & 0xFF)
        return unsigned + [0x00, 0x08, 0x00, 0x14] + hmac(unsigned, key: key)
    }
}

/// What `SipralStack(ice:stunServer:turn:)` carries, proven on the wire: the
/// mapping a STUN server reports reaches the `Contact` and the SDP a far end
/// reads, a TURN relay is asked for with the credential and offered as a
/// candidate, and two stacks that require ICE carry audio both ways.
final class NatTests: XCTestCase {
    /// An address of this machine's own that ICE may use: RFC 8445 §5.1.1.1
    /// keeps loopback out of the candidates, so the ICE tests bind every
    /// socket to the first interface that is up and not loopback. Nothing
    /// leaves the machine: every socket in them is this process's own.
    private func hostAddress() throws -> String {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { throw XCTSkip("no interfaces") }
        defer { freeifaddrs(list) }
        var found: String?
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(entry.pointee.ifa_flags)
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0 else { continue }
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { inet in
                var sin = inet.pointee.sin_addr
                _ = inet_ntop(AF_INET, &sin, &text, socklen_t(INET_ADDRSTRLEN))
            }
            found = String(cString: text)
            break
        }
        guard let found else { throw XCTSkip("no interface but loopback: ICE has no host candidate to test with") }
        return found
    }

    /// Waits for the first event `match` accepts, for up to `seconds`.
    private func first(
        _ events: AsyncStream<SipralEvent>, within seconds: Double = 10,
        where match: @escaping @Sendable (SipralEvent) -> Bool
    ) async -> SipralEvent? {
        await withTaskGroup(of: SipralEvent?.self) { group in
            group.addTask {
                for await event in events where match(event) { return event }
                return nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let found = await group.next() ?? nil
            group.cancelAll()
            return found
        }
    }

    /// The first datagram `peer` reads that starts with `prefix`, as text.
    private func read(_ peer: UDPSocket, startingWith prefix: String, within seconds: Double = 10) -> String? {
        let deadline = DispatchTime.now() + seconds
        while DispatchTime.now() < deadline {
            if let (data, _) = peer.receive() {
                let text = String(decoding: data, as: UTF8.self)
                if text.hasPrefix(prefix) { return text }
            } else {
                usleep(10_000)
            }
        }
        return nil
    }

    func testDefaultsAskNobody() throws {
        let stun = try FakeStunServer()
        defer { stun.stop() }
        stun.open = true
        let stack = try SipralStack()
        defer { stack.close() }
        XCTAssertNil(stack.stunServer)
        usleep(300_000)
        XCTAssertTrue(stun.requests.isEmpty)
    }

    func testStunMappingReachesContactAndSdp() async throws {
        let stun = try FakeStunServer()
        defer { stun.stop() }
        let peer = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { peer.close() }

        let alice = try SipralStack(stunServer: stun.address)
        defer { alice.close() }
        let events = alice.events()
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: peer.localAddress)
        stun.open = true

        let signalling = await first(events) { $0.natData?.signalling == true }
        let nat = try XCTUnwrap(signalling?.natData, "the STUN server's answer never became an event")
        XCTAssertEqual(nat.mapping, .learned)
        XCTAssertEqual(nat.local, alice.bindAddress)
        XCTAssertEqual(nat.mapped, FakeStunServer.mapped(alice.bindAddress))
        XCTAssertEqual(nat.accounts, 1)

        let call = try alice.placeCall(account: account, target: "sip:bob@\(peer.localAddress)")
        defer { call.close() }
        let mediaEvent = await first(events) { $0.natData?.signalling == false }
        let media = try XCTUnwrap(mediaEvent?.natData, "the media socket was never mapped")
        XCTAssertEqual(media.mapping, .learned)
        XCTAssertEqual(media.mapped, FakeStunServer.mapped(media.local))

        let invite = try XCTUnwrap(read(peer, startingWith: "INVITE "), "no INVITE reached the far end")
        let publicSignalling = FakeStunServer.mapped(alice.bindAddress)
        let publicMedia = UDPSocket.parse(FakeStunServer.mapped(media.local))
        XCTAssertTrue(
            invite.contains("Contact: <sip:alice@\(publicSignalling)") || invite.contains("@\(publicSignalling)"),
            "the INVITE's Contact does not name the public address:\n\(invite)"
        )
        XCTAssertFalse(invite.contains("@\(alice.bindAddress)>"), "the Contact still names the private socket")
        XCTAssertTrue(invite.contains("c=IN IP4 \(publicMedia.host)"), "the SDP does not name the public address")
        XCTAssertTrue(invite.contains("m=audio \(publicMedia.port) "), "the SDP does not name the public port")
        XCTAssertTrue(invite.contains("a=rtcp-mux"), "one mapping describes one port, so the offer asks for rtcp-mux")
    }

    func testTurnRelayIsAllocatedWithTheCredentialAndOffered() async throws {
        #if !canImport(CryptoKit)
        throw XCTSkip("the fake TURN server signs its answers with CryptoKit")
        #else
        let password = "turn-secret-\(UInt32.random(in: 100_000...999_999))"
        let turn = TurnServer(address: "", username: "alice-turn", password: password)
        XCTAssertFalse(turn.description.contains(password))
        XCTAssertFalse(String(reflecting: turn).contains(password))
        var dumped = ""
        dump(turn, to: &dumped)
        XCTAssertFalse(dumped.contains(password))

        let host = try hostAddress()
        let stun = try FakeStunServer(host: host, credential: ("alice-turn", password))
        defer { stun.stop() }
        let peer = try UDPSocket(host: host, port: 0)
        defer { peer.close() }

        let alice = try SipralStack(
            bindHost: host, ice: .offered, stunServer: stun.address,
            turn: TurnServer(address: stun.address, username: "alice-turn", password: password)
        )
        defer { alice.close() }
        let events = alice.events()
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: peer.localAddress)
        stun.open = true
        _ = await first(events) { $0.natData?.signalling == true }

        let call = try alice.placeCall(account: account, target: "sip:bob@\(peer.localAddress)", mediaHost: host)
        defer { call.close() }
        let relayEvent = await first(events) { $0.relayData != nil }
        let relay = try XCTUnwrap(relayEvent?.relayData, "no relay event")
        XCTAssertEqual(relay.outcome, .allocated, "relay failed: \(relay.code) \(relay.reason ?? "")")
        let relayed = try XCTUnwrap(relay.relayed)
        XCTAssertEqual(UDPSocket.parse(relayed).host, FakeStunServer.relayHost)

        let allocates = stun.requests.filter { $0.method == 0x0003 }
        let unsigned = try XCTUnwrap(allocates.first, "no Allocate reached the TURN server")
        XCTAssertNil(unsigned.attributes[0x0006], "the first Allocate carries no credential")
        let signed = try XCTUnwrap(allocates.first { $0.attributes[0x0006] != nil }, "no signed Allocate")
        XCTAssertEqual(signed.attributes[0x0006].map { String(decoding: $0, as: UTF8.self) }, "alice-turn")
        XCTAssertEqual(signed.attributes[0x0014].map { String(decoding: $0, as: UTF8.self) }, FakeStunServer.realm)
        XCTAssertEqual(signed.attributes[0x0015].map { String(decoding: $0, as: UTF8.self) }, FakeStunServer.nonce)
        XCTAssertEqual(stun.signedAllocateVerified, true, "the Allocate's MESSAGE-INTEGRITY is not the long-term key's")
        for request in stun.requests {
            XCTAssertFalse(
                String(decoding: request.bytes, as: UTF8.self).contains(password), "the password crossed the wire"
            )
        }

        let invite = try XCTUnwrap(read(peer, startingWith: "INVITE "), "no INVITE reached the far end")
        XCTAssertTrue(
            invite.contains("\(FakeStunServer.relayHost) \(UDPSocket.parse(relayed).port) typ relay"),
            "the offer does not carry the relay as a candidate:\n\(invite)"
        )
        #endif
    }

    func testTwoStacksRequiringIceCarryAudioBothWays() async throws {
        let host = try hostAddress()
        let alice = try SipralStack(bindHost: host, ice: .required)
        let bob = try SipralStack(bindHost: host, ice: .required)
        defer { alice.close(); bob.close() }
        try await assertIceCarriesAudio(alice, bob, host: host)
    }

    /// The same call with both ends behind the STUN server: every media
    /// socket is mapped before its call is described, so the far end's first
    /// checks arrive while the socket is still the stack's to read, and go
    /// in through `sipral_stack_receive_stun` until the media handle exists.
    /// The mapped address is this machine's own, on a port nothing listens
    /// on, so the server-reflexive pair fails and the host pair carries it.
    func testIceBehindStunCarriesAudioBothWays() async throws {
        let host = try hostAddress()
        let stun = try FakeStunServer(host: host, publicHost: host)
        defer { stun.stop() }
        stun.open = true
        let alice = try SipralStack(bindHost: host, ice: .required, stunServer: stun.address)
        let bob = try SipralStack(bindHost: host, ice: .required, stunServer: stun.address)
        defer { alice.close(); bob.close() }
        try await assertIceCarriesAudio(alice, bob, host: host)
        XCTAssertTrue(stun.requests.contains { $0.method == 0x0001 && $0.from != alice.bindAddress
            && $0.from != bob.bindAddress }, "no media socket asked the STUN server")
    }

    /// Task 8.5.5, `intern/rapoarte/2026-09-25-nat-layers.json`
    /// (`natmobile.review.findings[1]`): `SipralStack.drainFarewells` must
    /// send what `sipral_stack_poll_farewell` hands out to the destination
    /// it names -- the TURN server, for the Refresh with a lifetime of zero
    /// that gives a relay back (`crates/sipral/src/relay.rs`, "gives it
    /// back when the call ends") -- and only fall back to the last address
    /// media was heard from when it names none. A call whose peer never
    /// carries any ICE still had a relay allocated for it and still gives
    /// it back the same way (`relay.rs`: "A call whose peer does no ICE
    /// never uses it, and gives it back the same way"), so this needs
    /// nothing more than a call that reaches both ends and is then closed --
    /// were the destination ignored in favour of the far end's own address,
    /// as it once was, this fake TURN server would never see the Refresh at
    /// all.
    func testTurnAllocationIsGivenBackWhenTheCallEnds() async throws {
        #if !canImport(CryptoKit)
        throw XCTSkip("the fake TURN server signs its answers with CryptoKit")
        #else
        let password = "turn-secret-\(UInt32.random(in: 100_000...999_999))"
        let host = try hostAddress()
        let stun = try FakeStunServer(host: host, credential: ("alice-turn", password))
        defer { stun.stop() }

        let alice = try SipralStack(
            bindHost: host, ice: .offered, stunServer: stun.address,
            turn: TurnServer(address: stun.address, username: "alice-turn", password: password)
        )
        let bob = try SipralStack(bindHost: host)
        defer { alice.close(); bob.close() }
        let events = alice.events()
        let bobEvents = bob.events()
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        stun.open = true
        _ = await first(events) { $0.natData?.signalling == true }

        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)", mediaHost: host)
        let relayEvent = await first(events) { $0.relayData != nil }
        let relay = try XCTUnwrap(relayEvent?.relayData, "no relay event")
        XCTAssertEqual(relay.outcome, .allocated, "relay failed: \(relay.code) \(relay.reason ?? "")")

        let incoming = await first(bobEvents) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(incoming, "bob never saw the call"), mediaHost: host)
        try bobCall.answer()
        _ = await first(events) { $0.kind == .mediaPathChosen }

        aliceCall.close()
        bobCall.close()

        let deadline = DispatchTime.now() + 5
        while DispatchTime.now() < deadline {
            if stun.requests.contains(where: { $0.method == 0x0004 }) { break }
            usleep(20_000)
        }
        let refresh = try XCTUnwrap(
            stun.requests.first { $0.method == 0x0004 },
            "the TURN server never saw the Refresh that gives the relay back -- "
                + "the farewell went somewhere other than \(stun.address)"
        )
        let lifetime = try XCTUnwrap(refresh.attributes[0x000D], "the Refresh carries no LIFETIME")
        XCTAssertEqual(lifetime, [0, 0, 0, 0], "the Refresh does not ask for a lifetime of zero")
        #endif
    }

    private func assertIceCarriesAudio(_ alice: SipralStack, _ bob: SipralStack, host: String) async throws {
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = bob.events()
        let aliceStackEvents = alice.events()
        let aliceCall = try alice.placeCall(
            account: aliceAccount, target: "sip:bob@\(bob.bindAddress)", mediaHost: host
        )
        defer { aliceCall.close() }

        let incoming = await first(bobEvents) { $0.kind == .incomingCall }
        let offer = try XCTUnwrap(
            (incoming?.callData?.remoteSdp ?? incoming?.message).map { String(decoding: $0, as: UTF8.self) },
            "the incoming call carried neither its offer nor its message: \(String(describing: incoming))"
        )
        XCTAssertTrue(offer.contains("a=ice-ufrag:"), "the offer does not carry ICE:\n\(offer)")
        XCTAssertTrue(offer.contains("typ host"), "the offer has no host candidate:\n\(offer)")
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(incoming), mediaHost: host)
        defer { bobCall.close() }
        try bobCall.answer()

        let chosen = await first(aliceStackEvents) { $0.kind == .mediaPathChosen }
        XCTAssertNotNil(chosen, "ICE never chose a path")
        let deadline = DispatchTime.now() + 5
        while (aliceCall.media == nil || bobCall.media == nil) && DispatchTime.now() < deadline {
            usleep(20_000)
        }
        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)

        let tone = [Int16](repeating: 4096, count: aliceMedia.frameSamples * 25)
        aliceMedia.sendAudio(tone)
        bobMedia.sendAudio(tone)
        let until = DispatchTime.now() + 5
        while DispatchTime.now() < until {
            let a = try aliceMedia.statistics()
            let b = try bobMedia.statistics()
            if a.packets_received >= 10 && b.packets_received >= 10 { break }
            usleep(50_000)
        }
        XCTAssertGreaterThanOrEqual(try aliceMedia.statistics().packets_received, 10)
        XCTAssertGreaterThanOrEqual(try bobMedia.statistics().packets_received, 10)
    }
}
