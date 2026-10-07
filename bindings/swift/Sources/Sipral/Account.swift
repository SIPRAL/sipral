// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// The pinned certificate's validity dates (Unix seconds, zero if unreadable)
/// and whether the clock is outside them. Accepted either way; an expired
/// one deserves a warning.
public struct PinnedCertificate: Sendable, Equatable {
    public let notBefore: UInt64
    public let notAfter: UInt64
    public let expired: Bool
    public let notYetValid: Bool
}

/// `sipral_account_add`, and the entry points that take its handle.
///
/// Made by `SipralStack.addAccount`: a handle is only valid on the stack
/// that minted it, so the account keeps both.
public final class Account: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle
    public let aor: String
    /// Where requests go, `host:port`; with `serverUri`, the last located
    /// address, empty until then.
    public var registrarAddress: String { stateQueue.sync { _registrarAddress } }
    private var _registrarAddress: String
    /// The server named by a URI RFC 3263 locates, or `nil`.
    public let serverUri: String?
    /// `.tcp`, `.tls`, `.ws` or `.wss` for an account with its own
    /// connection, `nil` for the stack's transport.
    public let streamProtocol: SipralTransport?
    /// The certificate pin its own TLS connection is held to.
    let tlsPin: String?

    private let stateQueue = DispatchQueue(label: "org.sipral.account.state")
    /// The application's `Contact`, or `nil` when derived from the socket.
    private let givenContact: String?
    private var _contact: String

    /// The current `Contact`, updated by `SipralStack.networkChanged(to:)`.
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

    /// Whether the `Contact` is derived rather than written by the app.
    var derivesContact: Bool { givenContact == nil }

    /// The derived `Contact`'s transport parameter (RFC 3261 §19.1.1).
    var contactParameters: String {
        Self.contactParameters(streamProtocol, stack: stack)
    }

    static func contactParameters(_ streamProtocol: SipralTransport?, stack: SipralStack) -> String {
        switch streamProtocol {
        case .tcp: return ";transport=tcp"
        case .tls: return ";transport=tls"
        case .ws: return ";transport=ws"
        case .wss: return ";transport=wss"
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

    /// `sipral_account_check_certificate`: judge the server's leaf
    /// certificate (DER) against `tlsPin`, from the application's own TLS
    /// check. Returns `PinnedCertificate` when it matches (accept, whoever
    /// signed it, even expired), `nil` when nothing is pinned (the platform
    /// decides), and throws `.certificateRefused` otherwise.
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

    /// `sipral_account_rebind` after a network change. A derived `Contact`
    /// names the new socket; a written one has the old address replaced and
    /// is otherwise untouched.
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

    /// The standard `replacing(_:with:)` needs iOS 16 / macOS 13.
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

    /// The default `Contact`. Never the AOR: it names who this is, not a
    /// socket anything can reach.
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
        websocketHost: String? = nil,
        websocketResource: String? = nil,
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
        realms: [String],
        security: AccountSecurity
    ) throws -> Account {
        let given = contact
        let contact = contact ?? defaultContact(
            aor: aor, bindAddress: advertised ?? stack.bindAddress,
            parameters: contactParameters(streamProtocol, stack: stack)
        )
        let peers = trustedPeers.isEmpty ? nil : trustedPeers.joined(separator: ",")
        let named = realms.isEmpty ? nil : realms.joined(separator: "\n")
        let suites = security.srtpSuites.isEmpty ? nil : security.srtpSuites.joined(separator: ",")
        let key = security.stirKey ?? []
        let handle: SipralHandle = try CStrings.with(
            [aor, registrar, contact, registrarAddress, displayName, authUser, authPassword, peers,
             suites, security.stirCertificateUrl, security.stirOrig, security.stirOrigid, serverUri, tlsPin,
             named, websocketHost, websocketResource]
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
            if let realmsPointer = parts[14].pointer {
                config.realms = realmsPointer
                config.realms_len = parts[14].count
            }
            if let hostPointer = parts[15].pointer {
                config.websocket_host = hostPointer
                config.websocket_host_len = parts[15].count
            }
            if let resourcePointer = parts[16].pointer {
                config.websocket_resource = resourcePointer
                config.websocket_resource_len = parts[16].count
            }
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

    /// Asked to register and not since unregistered; such accounts
    /// re-register when a TCP/TLS connection is remade.
    public var wantsRegistration: Bool { stateQueue.sync { _wantsRegistration } }

    /// `sipral_account_register`. Refused for an account with no registrar.
    /// While a TCP/TLS connection is down the request is kept and sent once
    /// it is back.
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

    /// `sipral_account_set_access_token`: set or replace (or with `nil`,
    /// remove) the OAuth 2.0 token (RFC 8898), answering
    /// `SipralEventKind.tokenRequired`. Used for the next `Bearer`
    /// challenge; a registration that failed for lack of one restarts with
    /// `register()`. A token that is not an RFC 6750 `b64token` throws
    /// `.invalidArgument` and changes nothing.
    public func setAccessToken(_ token: String?) throws {
        try retryingBusy {
            try Sipral.accountSetAccessToken(stack: stack.handle, account: handle, token: token ?? "")
        }
    }

    /// A REGISTER with Expires: 0. The state reads unregistered at once; the
    /// registrar's answer is the following registration event. Wait for it
    /// before closing the stack, or a challenge to it goes unanswered.
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

    /// `sipral_account_announce`: called when a VoIP push arrives, possibly
    /// before its INVITE. Returns an announcement waiting for the INVITE, or
    /// the call if it already came.
    public func announce(caller: String) throws -> (announcement: SipralHandle?, call: SipralHandle?) {
        let result = try retryingBusy {
            try Sipral.accountAnnounce(stack: stack.handle, account: handle, caller: caller, nowMs: stack.nowMs())
        }
        if result.call != Sipral.handleNone {
            return (nil, result.call)
        }
        return (result.announcement, nil)
    }

    /// `sipral_account_refresh_binding` (RFC 8599 §4.1.3): refresh now on a
    /// wake-up, skipping schedule and back-off.
    public func refreshBinding() throws {
        try retryingBusy {
            try Sipral.accountRefreshBinding(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }

    // MARK: - subscriptions and presence

    /// `sipral_account_subscribe` (RFC 6665): watch `target` for `package`
    /// (`presence`, `conference`, `dialog`, `message-summary`, ...).
    /// `accept` overrides the default body type, `expiresSeconds` zero means
    /// an hour, and `destination` overrides where the SUBSCRIBE goes.
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

    /// Watch `target`'s presence (RFC 3856, PIDF). Each notification is a
    /// `presenceChanged` with `presenceData.kind == .watched`.
    public func watchPresence(of target: String, expiresSeconds: UInt32 = 0, destination: String? = nil) throws -> SipralSubscription {
        try subscribe(
            to: target, package: "presence", accept: "application/pidf+xml",
            expiresSeconds: expiresSeconds, destination: destination
        )
    }

    /// `sipral_account_publish_presence` (RFC 3903): publish to the
    /// registrar; later calls modify the same publication, kept refreshed
    /// until `unpublishPresence()`. Results arrive as `presenceChanged` with
    /// `presenceData.kind == .publication`.
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

/// An account's SRTP and STIR/SHAKEN settings (`srtp` and `stir_*` in
/// `sipral_account_config_t`).
///
/// `srtp` overrides the stack's policy (`nil` keeps it); a call may ask for
/// more, never less. `srtpSuites` are named by RFC 4568/7714, most preferred
/// first; GCM only if named. `stirVerification` applies once
/// `SipralStack.stir` set anchors. `stirKey` (P-256: raw 32 bytes, or SEC1
/// or PKCS #8 in DER or PEM) with `stirCertificateUrl` signs outgoing calls
/// (RFC 8224) as `stirOrig` or the AOR's number, with `stirAttestation`
/// (`.none` means A) and `stirOrigid` (generated when `nil`). Call
/// `SipralStack.stir` first, since a PASSporT needs the clock.
/// `recordingInClear` allows recording encrypted calls as plain RTP;
/// otherwise copies go as SRTP or not at all (RFC 7866 §12.2).
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
