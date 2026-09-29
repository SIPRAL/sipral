// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral
import Dispatch

/// `sipral_account_add`, and the entry points that take its handle.
///
/// Built through `SipralStack.addAccount`, never directly: a handle names
/// something only on the stack that minted it (`docs/08-ffi.md`, "A handle
/// names something only on the stack that minted it"), so keeping the two
/// together is what makes every method here safe to call with nothing
/// further to pass.
public final class Account: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle
    public let aor: String
    /// Where the account's requests go, `host:port`.
    public let registrarAddress: String

    private let stateQueue = DispatchQueue(label: "org.sipral.account.state")
    /// The `Contact` the application wrote, or `nil` when the account's is
    /// the one this layer derives from the signalling socket.
    private let givenContact: String?
    private var _contact: String

    /// Where this account says it can be reached, as its `Contact` carries
    /// it now: after `SipralStack.networkChanged(to:)`, the new address.
    public var contact: String { stateQueue.sync { _contact } }

    init(stack: SipralStack, handle: SipralHandle, aor: String, registrarAddress: String, contact: String, given: String?) {
        self.stack = stack
        self.handle = handle
        self.aor = aor
        self.registrarAddress = registrarAddress
        self._contact = contact
        self.givenContact = given
    }

    /// `sipral_account_rebind` onto the signalling socket the stack bound
    /// after a network change: a derived `Contact` names the new socket; one
    /// the application wrote has the old address, wherever it names it,
    /// replaced by the new one, and is otherwise left as written.
    func rebind(local now: String, previous: String?) throws {
        let next: String
        if givenContact == nil {
            next = Self.defaultContact(aor: aor, bindAddress: now, parameters: stack.contactParameters)
        } else if let previous, !previous.isEmpty {
            next = Self.replacing(previous, with: UDPSocket.parse(now).host, in: contact)
        } else {
            next = contact
        }
        try retryingBusy {
            try Sipral.accountRebind(
                stack: stack.handle, account: handle, transport: Sipral.transportMain,
                remote: registrarAddress, contact: next, nowMs: stack.nowMs()
            )
        }
        stateQueue.sync { _contact = next }
    }

    /// `text` with every `old` in it made `new`: the standard library's own
    /// `replacing(_:with:)` needs iOS 16 and macOS 13, and this package
    /// builds for older ones.
    private static func replacing(_ old: String, with new: String, in text: String) -> String {
        var result = ""
        var index = text.startIndex
        while index < text.endIndex {
            if text[index...].hasPrefix(old) {
                result += new
                index = text.index(index, offsetBy: old.count)
            } else {
                result.append(text[index])
                index = text.index(after: index)
            }
        }
        return result
    }

    /// Where this account can actually be reached, for a caller who gave no
    /// `Contact` of its own. The AOR itself is never a usable default: a
    /// `sip:` address of record names who this is, not a socket anything can
    /// write to (`bindings/python/sipral/account.py`'s `_default_contact`
    /// explains the same choice).
    private static func defaultContact(aor: String, bindAddress: String, parameters: String) -> String {
        guard let colon = aor.firstIndex(of: ":") else { return aor }
        let scheme = aor[aor.startIndex..<colon]
        let rest = aor[aor.index(after: colon)...]
        guard let at = rest.firstIndex(of: "@") else { return "\(scheme):\(bindAddress)\(parameters)" }
        let user = rest[rest.startIndex..<at]
        return "\(scheme):\(user)@\(bindAddress)\(parameters)"
    }

    static func add(
        stack: SipralStack,
        aor: String,
        registrarAddress: String,
        registrar: String?,
        contact: String?,
        displayName: String?,
        authUser: String?,
        authPassword: String?,
        expiresSeconds: UInt64,
        sessionTimer: SessionTimer,
        privacy: Privacy,
        trustedPeers: [String],
        security: AccountSecurity
    ) throws -> Account {
        let given = contact
        let contact = contact ?? defaultContact(
            aor: aor, bindAddress: stack.bindAddress, parameters: stack.contactParameters
        )
        let peers = trustedPeers.isEmpty ? nil : trustedPeers.joined(separator: ",")
        let suites = security.srtpSuites.isEmpty ? nil : security.srtpSuites.joined(separator: ",")
        let key = security.stirKey ?? []
        let handle: SipralHandle = try CStrings.with(
            [aor, registrar, contact, registrarAddress, displayName, authUser, authPassword, peers,
             suites, security.stirCertificateUrl, security.stirOrig, security.stirOrigid]
        ) { parts in
            var config = sipral_account_config_t.sized()
            config.aor = parts[0].pointer
            config.aor_len = parts[0].count
            if let registrarPointer = parts[1].pointer {
                config.registrar = registrarPointer
                config.registrar_len = parts[1].count
            }
            config.contact = parts[2].pointer
            config.contact_len = parts[2].count
            config.registrar_address = parts[3].pointer
            config.registrar_address_len = parts[3].count
            if let displayNamePointer = parts[4].pointer {
                config.display_name = displayNamePointer
                config.display_name_len = parts[4].count
            }
            if let authUserPointer = parts[5].pointer {
                config.auth_user = authUserPointer
                config.auth_user_len = parts[5].count
            }
            if let authPasswordPointer = parts[6].pointer {
                config.auth_password = authPasswordPointer
                config.auth_password_len = parts[6].count
            }
            config.expires_seconds = expiresSeconds
            let (timer, seconds) = sessionTimer.raw
            config.session_timer = timer
            config.session_interval_seconds = seconds
            config.privacy = privacy.rawValue
            if let peersPointer = parts[7].pointer {
                config.trusted_peers = peersPointer
                config.trusted_peers_len = parts[7].count
            }
            config.srtp = security.srtp?.rawValue ?? 0
            if let suitesPointer = parts[8].pointer {
                config.srtp_suites = suitesPointer
                config.srtp_suites_len = parts[8].count
            }
            config.stir_verification = security.stirVerification.rawValue
            if let urlPointer = parts[9].pointer {
                config.stir_certificate_url = urlPointer
                config.stir_certificate_url_len = parts[9].count
            }
            if let origPointer = parts[10].pointer {
                config.stir_orig = origPointer
                config.stir_orig_len = parts[10].count
            }
            if let origidPointer = parts[11].pointer {
                config.stir_origid = origidPointer
                config.stir_origid_len = parts[11].count
            }
            config.stir_attestation = security.stirAttestation.rawValue
            return try key.withUnsafeBufferPointer { keyBytes in
                if !keyBytes.isEmpty {
                    config.stir_key = keyBytes.baseAddress
                    config.stir_key_len = keyBytes.count
                }
                return try retryingBusy {
                    try Sipral.accountAdd(stack: stack.handle, config: config, configHeaders: [])
                }
            }
        }
        return Account(
            stack: stack, handle: handle, aor: aor, registrarAddress: registrarAddress, contact: contact, given: given
        )
    }

    private var _wantsRegistration = false

    /// Whether it was asked to register and not to unregister since: the
    /// accounts a stack signalling over TCP or TLS registers again once its
    /// connection is made again.
    public var wantsRegistration: Bool { stateQueue.sync { _wantsRegistration } }

    /// `sipral_account_register`. A no-op account (no registrar) refuses this.
    /// On a stack signalling over TCP or TLS whose connection is down
    /// (`.transportDown`, already raised as `SipralEventKind.transportFailed`)
    /// it is kept, and the REGISTER goes the moment the connection is made
    /// again.
    public func register() throws {
        stateQueue.sync { _wantsRegistration = true }
        do {
            try retryingBusy {
                try Sipral.accountRegister(stack: stack.handle, account: handle, nowMs: stack.nowMs())
            }
        } catch let refused as SipralError where refused.status == .transportDown {
            return
        }
    }

    public func unregister() throws {
        stateQueue.sync { _wantsRegistration = false }
        try retryingBusy {
            try Sipral.accountUnregister(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }

    public var registrationState: SipralRegistrationState? {
        get throws {
            let raw = try retryingBusy {
                try Sipral.accountRegistrationState(stack: stack.handle, account: handle)
            }
            return SipralRegistrationState(rawValue: raw)
        }
    }

    /// `sipral_account_remove`. Every call this account placed ends.
    public func remove() throws {
        try Sipral.accountRemove(stack: stack.handle, account: handle)
        stack.forgetAccount(handle)
    }

    /// `sipral_account_announce` (`docs/15-mobile.md`, "C2"): what a
    /// `PushKitBridge` calls the instant a VoIP push arrives, before the
    /// INVITE it is about has necessarily reached the transport. Returns
    /// either an announcement waiting for that INVITE, or the call itself
    /// when it arrived first.
    public func announce(caller: String) throws -> (announcement: SipralHandle?, call: SipralHandle?) {
        let result = try retryingBusy {
            try Sipral.accountAnnounce(stack: stack.handle, account: handle, caller: caller, nowMs: stack.nowMs())
        }
        if result.call != Sipral.handleNone {
            return (nil, result.call)
        }
        return (result.announcement, nil)
    }

    /// `sipral_account_refresh_binding` (RFC 8599 §4.1.3): refreshed at once
    /// on a wake-up, ahead of the scheduled refresh and any back-off an
    /// earlier outage earned.
    public func refreshBinding() throws {
        try retryingBusy {
            try Sipral.accountRefreshBinding(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }

    // MARK: - subscriptions and presence

    /// `sipral_account_subscribe` (RFC 6665): watch `target`, a SIP URI, for
    /// the event `package` -- `presence` (RFC 3856), `conference` (RFC 4575),
    /// `dialog` for a busy lamp field, `message-summary` -- from this
    /// account. `accept` is the `Accept` value when the package's default
    /// body type is not the one wanted, `expiresSeconds` how long to ask for
    /// (zero for an hour), and `destination` (`host:port`) where to send the
    /// SUBSCRIBE when not where the account registers.
    public func subscribe(
        to target: String,
        package: String,
        accept: String? = nil,
        expiresSeconds: UInt32 = 0,
        destination: String? = nil
    ) throws -> Subscription {
        let made = try CStrings.with([target, package, accept, destination]) { parts in
            var config = sipral_subscribe_config_t.sized()
            config.target = parts[0].pointer
            config.target_len = parts[0].count
            config.package = parts[1].pointer
            config.package_len = parts[1].count
            config.accept = parts[2].pointer
            config.accept_len = parts[2].count
            config.expires_seconds = expiresSeconds
            config.destination = parts[3].pointer
            config.destination_len = parts[3].count
            return try retryingBusy {
                try Sipral.accountSubscribe(stack: stack.handle, account: handle, config: config, nowMs: stack.nowMs())
            }
        }
        return Subscription(stack: stack, handle: made, package: package)
    }

    /// Watch `target`'s presence (RFC 3856): a `presence` subscription
    /// asking for PIDF, whose every notification arrives as
    /// `SipralEventKind.presenceChanged` with `presenceData.kind ==
    /// .watched`: open or closed, the activity, the presentity and its note.
    public func watchPresence(of target: String, expiresSeconds: UInt32 = 0, destination: String? = nil) throws -> Subscription {
        try subscribe(
            to: target, package: "presence", accept: "application/pidf+xml",
            expiresSeconds: expiresSeconds, destination: destination
        )
    }

    /// `sipral_account_publish_presence` (RFC 3903): publish this account's
    /// presence to its registrar as the presence compositor; the first call
    /// publishes and every later one modifies the same publication, which
    /// the stack keeps refreshed until `unpublishPresence()`. What the
    /// compositor did with it arrives as `SipralEventKind.presenceChanged`
    /// with `presenceData.kind == .publication`, naming this account.
    public func publishPresence(_ presence: Presence) throws {
        try CStrings.with([presence.note]) { parts in
            var document = sipral_presence_t.sized()
            document.basic = presence.basic.rawValue
            document.activity = presence.activity.rawValue
            document.note = parts[0].pointer
            document.note_len = parts[0].count
            try retryingBusy {
                try Sipral.accountPublishPresence(
                    stack: stack.handle, account: handle, presence: document, nowMs: stack.nowMs()
                )
            }
        }
    }

    /// `sipral_account_unpublish_presence`: take the published presence away;
    /// `.removed` says when it is gone. `.wrongState` when nothing is
    /// published.
    public func unpublishPresence() throws {
        try retryingBusy {
            try Sipral.accountUnpublishPresence(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }
}

/// What one account holds its calls to, and signs them with, beyond what the
/// stack does: the `srtp` and `stir_*` members of `sipral_account_config_t`,
/// given to `SipralStack.addAccount`.
///
/// `srtp` is the account's own SRTP policy over the stack's (`nil` keeps the
/// stack's); a call it places may ask for more and never less. `srtpSuites`
/// are the suites it runs, most preferred first, by their RFC 4568 and RFC
/// 7714 names; RFC 7714's GCM ones only if named. `stirVerification` is what
/// the account does with the `Identity` of the calls it receives, once
/// `SipralStack.stir` gave the stack trust anchors. `stirKey` (a P-256 key:
/// the bare 32 bytes, or SEC1 or PKCS #8 in DER or PEM) with
/// `stirCertificateUrl` signs every call the account places (RFC 8224), as
/// `stirOrig` or the number in the AOR, claiming `stirAttestation` (`.none`
/// is A) and `stirOrigid` (one drawn for the account when `nil`). A PASSporT
/// carries the time, which `SipralStack.stir` gives the stack: call it first,
/// with no anchors on a stack that only signs.
public struct AccountSecurity: Sendable {
    public var srtp: SipralSrtp?
    public var srtpSuites: [String]
    public var stirVerification: SipralStirVerification
    public var stirKey: [UInt8]?
    public var stirCertificateUrl: String?
    public var stirOrig: String?
    public var stirOrigid: String?
    public var stirAttestation: SipralAttestation

    public init(
        srtp: SipralSrtp? = nil,
        srtpSuites: [String] = [],
        stirVerification: SipralStirVerification = .default,
        stirKey: [UInt8]? = nil,
        stirCertificateUrl: String? = nil,
        stirOrig: String? = nil,
        stirOrigid: String? = nil,
        stirAttestation: SipralAttestation = .none
    ) {
        self.srtp = srtp
        self.srtpSuites = srtpSuites
        self.stirVerification = stirVerification
        self.stirKey = stirKey
        self.stirCertificateUrl = stirCertificateUrl
        self.stirOrig = stirOrig
        self.stirOrigid = stirOrigid
        self.stirAttestation = stirAttestation
    }
}
