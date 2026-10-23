// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// A TURN server (RFC 8656) and the long-term credential it knows this end
/// by: `sipral_stack_config_t::turn_server`, `turn_username` and
/// `turn_password`.
///
/// Each media socket gets a relay, offered as the relayed ICE candidate and
/// used only when no cheaper pair works (`docs/06-nat.md`). `address` is
/// `host:port`, not a name.
///
/// `transport` (RFC 8656 §3.1): `.udp` by default, `.tcp` where UDP is
/// blocked, `.tls` (port 5349) where only one port is open or the server
/// must be verified. The stack opens one connection per media socket. TLS
/// checks `serverName` (default: the host of `address`) against the system
/// roots, or only `trustedCertificates` (DER) when given. Checking cannot
/// be turned off. `clientIdentity` is presented when the server asks for a
/// client certificate; one that cannot be used now is no relay for that
/// call, as a refused connection is.
///
/// The password never appears in descriptions or logs: a leaked TURN
/// credential is a relay anyone can use.
public struct TurnServer: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let address: String
    public let username: String
    let password: String
    public let transport: SipralTransport
    public let serverName: String?
    public let trustedCertificates: [[UInt8]]
    public let clientIdentity: ClientIdentity?

    public init(
        address: String, username: String, password: String, transport: SipralTransport = .udp,
        serverName: String? = nil, trustedCertificates: [[UInt8]] = [], clientIdentity: ClientIdentity? = nil
    ) {
        self.address = address
        self.username = username
        self.password = password
        self.transport = transport
        self.serverName = serverName
        self.trustedCertificates = trustedCertificates
        self.clientIdentity = clientIdentity
    }

    public var description: String {
        "TurnServer(address: \(address), username: \(username), password: <redacted>, transport: \(transport))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "address": address, "username": username, "password": "<redacted>", "transport": transport,
            "serverName": serverName as Any, "trustedCertificates": trustedCertificates.count,
            "clientIdentity": clientIdentity != nil,
        ])
    }
}
