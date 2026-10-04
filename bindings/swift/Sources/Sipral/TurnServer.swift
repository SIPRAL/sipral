// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// A TURN server (RFC 8656) and the long-term credential it knows this end
/// by: `sipral_stack_config_t::turn_server`, `turn_username` and
/// `turn_password`.
///
/// Given to `SipralStack(stunServer:turn:)`, every media socket a call is
/// placed or answered on gets a relay there, offered as the call's relayed
/// ICE candidate -- the path of last resort, used only when no cheaper pair
/// answers (`docs/06-nat.md`). `address` is `host:port`, an address and
/// not a name.
///
/// `transport` is how every media socket reaches it (RFC 8656 §3.1):
/// `SipralTransport.udp` by default, `.tcp` for a network that lets no UDP
/// out, `.tls` for one that lets one port out -- 5349 is TURN's -- or for an
/// application that wants the server checked. Over either the stack opens a
/// connection per media socket itself, a Network.framework `NWConnection`,
/// and carries everything for the relay on it. Over TLS the certificate is
/// checked against `serverName` -- the host part of `address` when `nil`,
/// which for an address is an IP-address certificate -- with the system's
/// trust, or, when `trustedCertificates` holds any (DER), with those roots
/// and nothing else: how a private CA or a self-signed server is trusted.
/// Nothing here turns checking off.
///
/// The password never appears in `description`, `debugDescription`,
/// `dump()` or string interpolation: a TURN credential that reaches a log
/// is a relay somebody else can use.
public struct TurnServer: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let address: String
    public let username: String
    let password: String
    public let transport: SipralTransport
    public let serverName: String?
    public let trustedCertificates: [[UInt8]]

    public init(
        address: String, username: String, password: String, transport: SipralTransport = .udp,
        serverName: String? = nil, trustedCertificates: [[UInt8]] = []
    ) {
        self.address = address
        self.username = username
        self.password = password
        self.transport = transport
        self.serverName = serverName
        self.trustedCertificates = trustedCertificates
    }

    public var description: String {
        "TurnServer(address: \(address), username: \(username), password: <redacted>, transport: \(transport))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "address": address, "username": username, "password": "<redacted>", "transport": transport,
            "serverName": serverName as Any, "trustedCertificates": trustedCertificates.count,
        ])
    }
}
