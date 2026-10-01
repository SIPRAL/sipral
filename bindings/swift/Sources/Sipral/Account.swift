// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// What `Account.checkCertificate(_:unixSeconds:)` found in the certificate
/// the account pins: its dates, in seconds since 1970 (zero when its DER
/// could not be read that far), and whether the clock is past or before
/// them. Accepted either way; an expired one is worth a warning.
public struct PinnedCertificate: Sendable, Equatable {
    public let notBefore: UInt64
    public let notAfter: UInt64
    public let expired: Bool
    public let notYetValid: Bool
}

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
    /// Where the account's requests go, `host:port`: the address it was
    /// added with, or -- for one added with `serverUri` -- the address it was
    /// last located at, empty until then.
    public var registrarAddress: String { stateQueue.sync { _registrarAddress } }
    private var _registrarAddress: String
    /// The server named by a URI RFC 3263 locates, or `nil`.
    public let serverUri: String?
    /// The protocol of the connection of its own the account's requests go
    /// over, `.tcp` or `.tls`, or `nil` for the stack's own transport
    /// (`SipralStack.addAccount(streamProtocol:)`).
    public let streamProtocol: SipralTransport?
    /// The certificate pin it was added with, which a TLS connection of its
    /// own is held to.
    let tlsPin: String?

    private let stateQueue = DispatchQueue(label: "org.sipral.account.state")
    /// The `Contact` the application wrote, or `nil` when the account's is
    /// the one this layer derives from the signalling socket.
    private let givenContact: String?
    private var _contact: String

    /// Where this account says it can be reached, as its `Contact` carries
    /// it now: after `SipralStack.networkChanged(to:)`, the new address.
    public var contact: String { stateQueue.sync { _contact } }

    init(
        stack: SipralStack, handle: SipralHandle, aor: String, registrarAddress: String, serverUri: String?,
        contact: String, given: String?, streamProtocol: SipralTransport? = nil, tlsPin: String? = nil
    ) {
        self.stack = stack
        self.handle = handle
        self.aor = aor
        self._registrarAddress = registrarAddress
        self.serverUri = serverUri
        self.streamProtocol = streamProtocol
        self.tlsPin = tlsPin
        self._contact = contact
        self.givenContact = given
    }

    /// Whether its `Contact` is the one this layer derives, rather than one
    /// the application wrote.
    var derivesContact: Bool { givenContact == nil }

    /// What goes after the address in the `Contact` this layer derives for
    /// it: the parameter naming its own connection's protocol (RFC 3261
    /// §19.1.1), or the stack's.
    var contactParameters: String {
        Self.contactParameters(streamProtocol, stack: stack)
    }

    static func contactParameters(_ streamProtocol: SipralTransport?, stack: SipralStack) -> String {
        switch streamProtocol {
        case .tcp: return ";transport=tcp"
        case .tls: return ";transport=tls"
        default: return stack.contactParameters
        }
    }

    /// The account's server was located at `target`.
    func located(at target: String) {
        stateQueue.sync { _registrarAddress = target }
    }

    /// `sipral_account_rebind` toward `remote`, reached at `advertised`
    /// (`host:port`), unless its `Contact` names that already.
    func reach(at advertised: String, remote: String) throws {
        let next = Self.defaultContact(aor: aor, bindAddress: advertised, parameters: contactParameters)
        guard next != contact else { return }
        try retryingBusy {
            try Sipral.accountRebind(
                stack: stack.handle, account: handle, transport: Sipral.transportMain,
                remote: remote, contact: next, nowMs: stack.nowMs()
            )
        }
        stateQueue.sync { _contact = next }
    }

    /// `sipral_account_check_certificate`: the verdict of this account's
    /// `tlsPin` on `certificate`, the DER bytes of the leaf a TLS server
    /// presented, from inside the application's own certificate check. A
    /// `PinnedCertificate` when it is the pinned one -- accept the handshake
    /// whoever signed it, its dates reported, an expired one included; `nil`
    /// when the account pins nothing and the platform's own checks decide;
    /// `.certificateRefused` thrown when it pins another.
    public func checkCertificate(_ certificate: [UInt8], unixSeconds: UInt64? = nil) throws -> PinnedCertificate? {
        let now = unixSeconds ?? UInt64(time(nil))
        let found = try retryingBusy {
            try Sipral.accountCheckCertificate(stack: stack.handle, account: handle, certificate: certificate, unixSeconds: now)
        }
        guard found.pinned != 0 else { return nil }
        return PinnedCertificate(
            notBefore: found.not_before, notAfter: found.not_after,
            expired: found.expired != 0, notYetValid: found.not_yet_valid != 0
        )
    }

    /// `sipral_account_rebind` onto the signalling socket the stack bound
    /// after a network change: a derived `Contact` names the new socket; one
    /// the application wrote has the old address, wherever it names it,
    /// replaced by the new one, and is otherwise left as written.
    func rebind(local now: String, previous: String?) throws {
        let next: String
        if givenContact == nil {
            next = Self.defaultContact(aor: aor, bindAddress: now, parameters: contactParameters)
        } else if let previous, !previous.isEmpty {
            next = Self.replacing(previous, with: UDPSocket.parse(now).host, in: contact)
        } else {
            next = contact
        }
        try retryingBusy {
            try Sipral.accountRebind(
                stack: stack.handle, account: handle, transport: Sipral.transportMain,
                remote: self.registrarAddress, contact: next, nowMs: stack.nowMs()
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
        registrarAddress: String?,
        serverUri: String?,
        serverNaptr: Bool,
        keepaliveMs: UInt64,
        tlsPin: String?,
        streamProtocol: SipralTransport?,
        advertised: String?,
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
            aor: aor, bindAddress: advertised ?? stack.bindAddress,
            parameters: contactParameters(streamProtocol, stack: stack)
        )
        let peers = trustedPeers.isEmpty ? nil : trustedPeers.joined(separator: ",")
        let suites = security.srtpSuites.isEmpty ? nil : security.srtpSuites.joined(separator: ",")
        let key = security.stirKey ?? []
        let handle: SipralHandle = try CStrings.with(
            [aor, registrar, contact, registrarAddress, displayName, authUser, authPassword, peers,
             suites, security.stirCertificateUrl, security.stirOrig, security.stirOrigid, serverUri, tlsPin]
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
            if let registrarAddressPointer = parts[3].pointer {
                config.registrar_address = registrarAddressPointer
                config.registrar_address_len = parts[3].count
            }
            if let serverUriPointer = parts[12].pointer {
                config.server_uri = serverUriPointer
                config.server_uri_len = parts[12].count
            }
            if let pinPointer = parts[13].pointer {
                config.tls_pin_sha256 = pinPointer
                config.tls_pin_sha256_len = parts[13].count
            }
            config.server_naptr = serverNaptr ? SipralToggle.on.rawValue : 0
            config.keepalive_ms = keepaliveMs
            config.stream_protocol = streamProtocol?.rawValue ?? 0
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
            config.recording_in_clear = security.recordingInClear ? UInt64(SipralToggle.on.rawValue) : 0
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
            stack: stack, handle: handle, aor: aor, registrarAddress: registrarAddress ?? "", serverUri: serverUri,
            contact: contact, given: given, streamProtocol: streamProtocol, tlsPin: tlsPin
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
    ) throws -> SipralSubscription {
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
        return SipralSubscription(stack: stack, handle: made, package: package)
    }

    /// Watch `target`'s presence (RFC 3856): a `presence` subscription
    /// asking for PIDF, whose every notification arrives as
    /// `SipralEventKind.presenceChanged` with `presenceData.kind ==
    /// .watched`: open or closed, the activity, the presentity and its note.
    public func watchPresence(of target: String, expiresSeconds: UInt32 = 0, destination: String? = nil) throws -> SipralSubscription {
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
/// with no anchors on a stack that only signs. `recordingInClear` lets the
/// account's encrypted calls be recorded to a recording server as plain RTP;
/// otherwise their copies go as SRTP or not at all (RFC 7866 §12.2).
public struct AccountSecurity: Sendable {
    public var srtp: SipralSrtp?
    public var srtpSuites: [String]
    public var stirVerification: SipralStirVerification
    public var stirKey: [UInt8]?
    public var stirCertificateUrl: String?
    public var stirOrig: String?
    public var stirOrigid: String?
    public var stirAttestation: SipralAttestation
    public var recordingInClear: Bool

    public init(
        srtp: SipralSrtp? = nil,
        srtpSuites: [String] = [],
        stirVerification: SipralStirVerification = .default,
        stirKey: [UInt8]? = nil,
        stirCertificateUrl: String? = nil,
        stirOrig: String? = nil,
        stirOrigid: String? = nil,
        stirAttestation: SipralAttestation = .none,
        recordingInClear: Bool = false
    ) {
        self.srtp = srtp
        self.srtpSuites = srtpSuites
        self.stirVerification = stirVerification
        self.stirKey = stirKey
        self.stirCertificateUrl = stirCertificateUrl
        self.stirOrig = stirOrig
        self.stirOrigid = stirOrigid
        self.stirAttestation = stirAttestation
        self.recordingInClear = recordingInClear
    }
}
