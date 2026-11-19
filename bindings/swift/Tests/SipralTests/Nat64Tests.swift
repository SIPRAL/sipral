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

/// A network with IPv6 only reaches IPv4 servers through its NAT64 (RFC 6052,
/// RFC 7050); the sockets translate and the stack keeps seeing IPv4.
final class Nat64Tests: XCTestCase {
    override func tearDown() {
        Nat64.assume([])
        Nat64.forget()
        super.tearDown()
    }

    /// RFC 6052 §2.4, Table 1: 192.0.2.33 in each prefix length, both ways.
    func testAnAddressGoesIntoEveryPrefixLengthAndComesBackOut() throws {
        let table = [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::c000:221"),
            ("64:ff9b::/96", "64:ff9b::c000:221"),
        ]
        for (prefixText, embedded) in table {
            let prefix = try XCTUnwrap(Nat64Prefix(prefixText), prefixText)
            XCTAssertEqual(prefix.synthesize("192.0.2.33"), embedded, prefixText)
            XCTAssertEqual(prefix.extract(embedded), "192.0.2.33", prefixText)
        }
        XCTAssertEqual(Nat64Prefix.wellKnown, Nat64Prefix("64:ff9b::/96"))
    }

    func testAnAddressOutsideThePrefixOrWithBits64To71SetCarriesNoIpv4() throws {
        let prefix = try XCTUnwrap(Nat64Prefix("2001:db8:122::/48"))
        XCTAssertNil(prefix.extract("2001:db9:122:c000:2:2100::"), "another prefix")
        XCTAssertNil(prefix.extract("2001:db8:122:c000:2:2100::".replacingOccurrences(of: ":2:", with: ":102:")),
                     "bits 64-71 must be zero")
        XCTAssertNil(Nat64Prefix("2001:db8::/36"), "a length RFC 6052 does not define")
        XCTAssertNil(Nat64Prefix("192.0.2.0/32"))
        XCTAssertEqual(Nat64Prefix("2001:db8::ffff/32")?.description, "2001:db8::/32", "what lies past the length is cleared")
    }

    /// RFC 7050 §3: the length is where 192.0.0.170 sits in the answer for
    /// ipv4only.arpa, else 192.0.0.171; each prefix once, in answer order.
    func testADns64AnswerRevealsItsPrefixes() throws {
        let first = try XCTUnwrap(Nat64Prefix("2001:db8:122:300::/56"))
        let second = Nat64Prefix.wellKnown
        let answers = [
            first.synthesize([192, 0, 0, 170]),
            first.synthesize([192, 0, 0, 171]),
            second.synthesize([192, 0, 0, 171]),
        ]
        XCTAssertEqual(Nat64Prefix.revealed(by: answers), [first, second])
        XCTAssertEqual(Nat64Prefix.revealed(by: [try XCTUnwrap(Nat64Prefix.octets(of: "2001:db8::1"))]), [])
        XCTAssertEqual(Nat64Prefix.revealed(by: []), [])
    }

    func testAnAnswerHoldingTheKnownAddressAtTwoLengthsRevealsNothing() throws {
        // 192.0.0.170 at bits 32-63 reads so for /32, and again at bits
        // 96-127 for /96: which length the server meant cannot be told
        var address = try XCTUnwrap(Nat64Prefix("2001:db8::/32")).synthesize([192, 0, 0, 170])
        address.replaceSubrange(12..<16, with: [192, 0, 0, 170])
        XCTAssertEqual(Nat64Prefix.revealed(by: [address]), [])
    }

    func testAnIpv4DestinationWithNoRouteGoesThroughThePrefixFound() throws {
        XCTAssertNil(UDPSocket.translated("192.0.2.33", after: ENETUNREACH), "no prefix found")
        Nat64.assume([Nat64Prefix.wellKnown])
        let through = try XCTUnwrap(UDPSocket.translated("192.0.2.33", after: ENETUNREACH))
        XCTAssertEqual(Nat64Prefix.text(of: through), "64:ff9b::c000:221")
        XCTAssertNotNil(UDPSocket.translated("192.0.2.33", after: EHOSTUNREACH))
        XCTAssertNil(UDPSocket.translated("192.0.2.33", after: ECONNREFUSED), "an answer, not a missing route")
        XCTAssertNil(UDPSocket.translated("[2001:db8::1]", after: ENETUNREACH), "not IPv4")
    }

    func testOnlyALoopbackOrLinkLocalRouteTowardAPeerThatIsNeitherIsUnroutable() {
        XCTAssertTrue(SipralStack.unroutable("127.0.0.1", toward: "192.0.2.33:5060"))
        XCTAssertTrue(SipralStack.unroutable("169.254.10.2", toward: "192.0.2.33:5060"))
        XCTAssertFalse(SipralStack.unroutable("10.0.0.5", toward: "192.0.2.33:5060"))
        XCTAssertFalse(SipralStack.unroutable("127.0.0.1", toward: "127.0.0.1:5060"))
    }

    /// The stack's socket binds both families; an IPv4 peer is still given
    /// and reported as IPv4, and an address inside a prefix found as the
    /// IPv4 it carries. `::/96` puts 0.0.0.1 on `::1`, so loopback stands in
    /// for the translator.
    func testASocketOfBothFamiliesTalksIpv4AndReportsTranslatedPeersAsIpv4() throws {
        let both = try UDPSocket(host: "0.0.0.0", port: 0)
        defer { both.close() }
        let v4 = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { v4.close() }
        let v6 = try UDPSocket(host: "::1", port: 0)
        defer { v6.close() }
        XCTAssertEqual(both.family, AF_INET6)
        XCTAssertTrue(v6.localAddress.hasPrefix("[::1]:"), v6.localAddress)
        let bothPort = UDPSocket.parse(both.localAddress).port

        XCTAssertTrue(both.send([1], to: v4.localAddress))
        let atV4 = try XCTUnwrap(Self.next(v4))
        XCTAssertEqual(atV4.from, "127.0.0.1:\(bothPort)")
        XCTAssertTrue(v4.send([2], to: "127.0.0.1:\(bothPort)"))
        XCTAssertEqual(try XCTUnwrap(Self.next(both)).from, v4.localAddress, "a mapped address comes back as IPv4")

        XCTAssertTrue(v6.send([3], to: "[::1]:\(bothPort)"))
        let v6Port = UDPSocket.parse(v6.localAddress).port
        XCTAssertEqual(try XCTUnwrap(Self.next(both)).from, "[::1]:\(v6Port)")
        Nat64.assume([try XCTUnwrap(Nat64Prefix("::/96"))])
        XCTAssertTrue(v6.send([4], to: "[::1]:\(bothPort)"))
        XCTAssertEqual(try XCTUnwrap(Self.next(both)).from, "0.0.0.1:\(v6Port)", "inside the prefix: the IPv4 it carries")
    }

    func testTheNat64HostAddressBindsEverythingAndKeepsItsName() throws {
        let socket = try UDPSocket(host: Nat64.hostAddress, port: 0)
        defer { socket.close() }
        XCTAssertTrue(socket.localAddress.hasPrefix("192.0.0.4:"), socket.localAddress)
        let peer = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { peer.close() }
        XCTAssertTrue(socket.send([5], to: peer.localAddress))
        XCTAssertNotNil(Self.next(peer))
    }

    #if canImport(Network)
    func testAStreamToAnIpv4ServerMadeFromIpv6NamesThisMachineByTheNat64HostAddress() {
        XCTAssertEqual(SignallingConnection.named("[2001:db8::5]:50123", toward: "192.0.2.33"), "192.0.0.4:50123")
        XCTAssertEqual(SignallingConnection.named("10.0.0.5:50123", toward: "192.0.2.33"), "10.0.0.5:50123")
        XCTAssertEqual(SignallingConnection.named("[2001:db8::5]:50123", toward: "2001:db8::9"), "[2001:db8::5]:50123")
    }
    #endif

    /// The next datagram at `socket`, waiting up to ten seconds: a security
    /// filter may hold a binary's first loopback traffic for a while.
    private static func next(_ socket: UDPSocket) -> (data: [UInt8], from: String)? {
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if let got = socket.receive() { return got }
            usleep(2000)
        }
        return nil
    }
}
