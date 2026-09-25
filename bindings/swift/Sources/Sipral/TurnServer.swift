// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
/// The password never appears in `description`, `debugDescription`,
/// `dump()` or string interpolation: a TURN credential that reaches a log
/// is a relay somebody else can use.
public struct TurnServer: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let address: String
    public let username: String
    let password: String

    public init(address: String, username: String, password: String) {
        self.address = address
        self.username = username
        self.password = password
    }

    public var description: String {
        "TurnServer(address: \(address), username: \(username), password: <redacted>)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["address": address, "username": username, "password": "<redacted>"])
    }
}
