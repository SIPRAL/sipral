// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import Sipral

/// A carrier gateway's call through the Swift layer: an INVITE whose body is
/// the SDP beside the ISUP IAM of the call (RFC 3204, SIP-I), sent by hand
/// from a socket of the test's own, read into `CallerIdentity`.
final class IsupTests: XCTestCase {
    /// An IAM written out octet by octet from ITU-T Q.763 (Table 32,
    /// Figure 3): a call to the national number 5555550102 from
    /// +15555550100, presentation restricted and network provided, diverted
    /// once on no reply from +15555550101.
    private static let iam: [UInt8] = [
        0x01, // initial address
        0x00, // nature of connection indicators
        0x20, 0x01, // forward call indicators: ISUP all the way; ISDN access
        0x0a, // calling party's category: ordinary subscriber
        0x03, // transmission medium requirement: 3.1 kHz audio
        0x02, 0x09, // pointers: the called party number, the optional part
        0x07, 0x03, 0x10, 0x55, 0x55, 0x55, 0x10, 0x20, // called: even, national; ISDN; 5555550102
        0x0a, 0x08, 0x84, 0x17, 0x51, 0x55, 0x55, 0x05, 0x01, 0x00, // calling: odd, international; restricted, network
        0x0b, 0x08, 0x84, 0x10, 0x51, 0x55, 0x55, 0x05, 0x01, 0x01, // redirecting: odd, international
        0x13, 0x02, 0x23, 0x21, // redirection information: diverted, no reply; counter 1, no reply
        0x00, // end of optional parameters
    ]

    private static let offer = """
    v=0\r
    o=- 1 1 IN IP4 127.0.0.1\r
    s=-\r
    c=IN IP4 127.0.0.1\r
    t=0 0\r
    m=audio 40000 RTP/AVP 0\r
    a=rtpmap:0 PCMU/8000\r

    """

    func testACarrierGatewaysCallerIsReadFromTheIamBesideTheOffer() async throws {
        let gateway = try UDPSocket(host: "127.0.0.1", port: 0)
        let bob = try SipralStack(audio: .application)
        defer { bob.close() }
        _ = try bob.addAccount(
            aor: "sip:bob@sipral.invalid", registrarAddress: gateway.localAddress, trustedPeers: ["127.0.0.1"]
        )
        let events = Recorder(bob.events())

        var body = Array("--isup\r\nContent-Type: application/sdp\r\n\r\n\(Self.offer)\r\n--isup\r\n".utf8)
        body += Array("Content-Type: application/ISUP;version=itu-t92+\r\nContent-Disposition: signal;handling=required\r\n\r\n".utf8)
        body += Self.iam
        body += Array("\r\n--isup--\r\n".utf8)
        var invite = Array((
            "INVITE sip:bob@\(bob.bindAddress) SIP/2.0\r\n"
                + "Via: SIP/2.0/UDP \(gateway.localAddress);branch=z9hG4bK-isup-swift\r\n"
                + "Max-Forwards: 70\r\n"
                + "From: \"Anonymous\" <sip:anonymous@anonymous.invalid>;tag=gw\r\n"
                + "To: <sip:bob@sipral.invalid>\r\n"
                + "Call-ID: isup-swift@127.0.0.1\r\n"
                + "CSeq: 1 INVITE\r\n"
                + "Contact: <sip:gw@\(gateway.localAddress)>\r\n"
                + "Content-Type: multipart/mixed;boundary=isup\r\n"
                + "Content-Length: \(body.count)\r\n\r\n"
        ).utf8)
        invite += body
        XCTAssertTrue(gateway.send(invite, to: bob.bindAddress), "the INVITE did not go")

        let arrived = await events.first(within: 5) { $0.kind == .incomingCall }
        let ringing = try XCTUnwrap(arrived, "the gateway's call was not rung")
        let identity = try bob.callerIdentity(of: ringing)
        XCTAssertEqual(
            identity.isup,
            IsupCaller(calling: "+15555550100", additionalCalling: [], originalCalled: nil, redirecting: "+15555550101")
        )
        XCTAssertEqual(identity.asserted?.uri, "tel:+15555550100", "a trusted gateway's number is the asserted one")
        XCTAssertTrue(identity.privacy.contains(.id), "a withheld number stays withheld")
        XCTAssertEqual(identity.diversions, [Diversion(uri: "tel:+15555550101", displayName: nil, reason: "no-answer")])
    }
}
