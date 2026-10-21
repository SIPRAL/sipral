// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// What an account's REGISTER tells the network about waking this device
/// (RFC 8599): `SipralStack.addAccount(push:)`.
///
/// The parameters go on the `Contact` URI of every REGISTER and nowhere
/// else; a de-registration leaves `pn-prid` out (§4.1.2). For APNs the
/// provider is `apns`, `prid` the device token PushKit handed over, in hex,
/// and `param` the team and topic, `TEAMID.org.example.app.voip` (§10).
public struct SipralPush: Sendable, Equatable {
    /// `pn-provider`: `apns`, `fcm` or `webpush`.
    public var provider: String
    /// `pn-prid`: the device token the push service issued.
    public var prid: String
    /// `pn-param`: what the service needs besides, or `nil`.
    public var param: String?
    /// `+sip.pnsreg`: this device refreshes its binding without being woken.
    /// Only the application knows; a process the system suspends does not.
    public var wakesItself: Bool

    public init(provider: String, prid: String, param: String? = nil, wakesItself: Bool = false) {
        self.provider = provider
        self.prid = prid
        self.param = param
        self.wakesItself = wakesItself
    }

    /// APNs VoIP pushes for `bundleId` under `teamId`, with PushKit's token.
    public static func apnsVoip(token: [UInt8], teamId: String, bundleId: String) -> SipralPush {
        SipralPush(
            provider: "apns",
            prid: token.map { byte in
                let digits = Array("0123456789abcdef")
                return String([digits[Int(byte >> 4)], digits[Int(byte & 0x0f)]])
            }.joined(),
            param: "\(teamId).\(bundleId).voip"
        )
    }
}

/// What the registrar said about push in its 2xx (`Account.pushEcho()`).
public struct SipralPushEcho: Sendable, Equatable {
    /// The network promised notifications of the service asked for
    /// (`+sip.pns`, §4.1.1). `false` means nobody said so: an application
    /// that lets itself be suspended on the strength of it stops ringing.
    public let accepted: Bool
    /// How long before the binding lapses the network wants a refresh
    /// (`+sip.pnsreg`, §4.1.4), or `nil` when it named none.
    public let refreshLeadMs: UInt64?

    init(_ raw: sipral_push_echo_t) {
        accepted = raw.accepted != 0
        refreshLeadMs = raw.has_refresh_lead != 0 ? raw.refresh_lead_ms : nil
    }
}

extension Account {
    /// `sipral_account_push_echo`: the registrar's answer to the push
    /// parameters. Throws `.notSupported` for an account added without
    /// `push`, or one with no standing binding.
    public func pushEcho() throws -> SipralPushEcho {
        SipralPushEcho(try retryingBusy { try Sipral.accountPushEcho(stack: stack.handle, account: handle) })
    }
}
