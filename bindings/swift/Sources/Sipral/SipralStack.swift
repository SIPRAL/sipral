// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// One `sipral_stack_create` handle, its socket and its poll thread.
///
/// It owns the signalling socket, a background thread that drains
/// `sipral_stack_poll`, and the `AsyncStream`s events land on.
///
/// **Threading.** The C callback runs on the poll thread and is decoded
/// there into a `Sendable` `SipralEvent`, so nothing outlives the pointers
/// `sipral_event_t` only lends for the callback. Every other member may be
/// called from any thread; a collision with the poll thread
/// (`SIPRAL_STATUS_BUSY`) is retried for up to half a second before it is
/// thrown (`docs/08-ffi.md`).
public final class SipralStack: @unchecked Sendable {
    public let handle: SipralHandle

    /// The signalling address, `host:port`, as currently bound. Over TCP or
    /// TLS, the local end of the current connection. With no `bindHost`, the
    /// address advertised: the route toward the first account's server.
    public var bindAddress: String {
        signallingQueue.sync { advertisedLocal ?? socket?.localAddress ?? linkLocal }
    }

    /// UDP, or one TCP or TLS connection to the server.
    public let signalling: SipralTransport

    /// Whether SIP can go out now: always over UDP, and over TCP or TLS
    /// while the connection to the server stands.
    public var connected: Bool {
        signalling == .udp || signallingQueue.sync { link != nil }
    }

    /// Who runs this stack's audio, as it was created.
    public let audioMode: AudioMode

    /// The library's audio engine in `AudioMode.device`; `nil` in
    /// `.application`.
    public private(set) var audio: AudioDevices?

    private let eventBroadcast = Broadcast<SipralEvent>(
        label: "org.sipral.stack.events", policy: .bufferingNewest(Call.eventBuffer)
    )

    /// A new reader of every event this stack raises. For one call's events,
    /// use `Call.events()`.
    ///
    /// Each stream gets every event raised after it is taken, in order, so
    /// take it before the action whose outcome it should see (before
    /// `Account.register()`, before placing the call). Each buffers up to
    /// `Call.eventBuffer` events and drops its oldest past that. Streams
    /// finish on `close()`; one taken after that is already finished.
    public func events() -> AsyncStream<SipralEvent> {
        eventBroadcast.stream()
    }

    /// Guarded by `signallingQueue`: `networkChanged(to:)` replaces it.
    private var socket: UDPSocket?
    private let signallingQueue = DispatchQueue(label: "org.sipral.stack.signalling")
    /// The TCP or TLS connection and its local address, guarded by
    /// `signallingQueue`; `nil` while down.
    private var link: SignallingConnection?
    private var linkLocal = ""
    /// Where the connection goes, what name its certificate must carry, what
    /// it trusts, and the address it is made from.
    private let signallingServer: String?
    private let tlsServerName: String
    private let tlsTrust: TLSTrust
    private var linkHost: String?
    /// What a socket bound on every interface advertises; `nil` when bound
    /// at one address. Guarded by `signallingQueue`.
    private var advertisedLocal: String?
    private var routeChosen: Bool
    /// No `bindHost` was given, so the address is picked again on every
    /// network change.
    private let routes: Bool
    /// The chosen signalling port (zero: system's choice), rebound by
    /// `networkChanged(to:)`.
    private let chosenPort: UInt16
    private var _keptSignallingPort = true

    /// Whether the last `networkChanged(to:)` kept the UDP signalling port.
    /// `false` when the port was taken at the new address and the system
    /// chose another (see `bindAddress`): peers or firewall rules that know
    /// the old port must be told. `true` before any change.
    public var keptSignallingPort: Bool {
        signallingQueue.sync { _keptSignallingPort }
    }
    /// Answers `SipralEventKind.lookupWanted`.
    private let resolver: SipralResolver
    /// Collected during a poll and acted on after it; guarded by
    /// `signallingQueue`.
    private var lookupsAsked: [(account: SipralHandle, name: String, record: UInt32)] = []
    private var locatedAsked: [(account: SipralHandle, target: String)] = []
    private var reconnecting = false
    private let origin: DispatchTime
    /// Recording-server connections by transport id; `signallingQueue`.
    private var recordingLinks: [UInt32: SignallingConnection] = [:]
    /// One counter for every kind of connection, so two never share an id
    /// (`takeLinkId()`). Guarded by `signallingQueue`.
    var nextLink: UInt32 = SipralStack.firstLink
    /// Whether a request too large for a datagram gets a connection
    /// (`streamFallback`).
    private let streamFallback: Bool
    /// Where such a connection goes, when not to the address asked for
    /// (`streamServer`).
    private let streamServer: String?
    /// Connections for requests too large for a datagram, those being
    /// opened, and those asked for during the current poll. All guarded by
    /// `signallingQueue`.
    private var streamLinks: [UInt32: (destination: String, link: SignallingConnection)] = [:]
    private var streamsOpening: Set<String> = []
    private var streamsAsked: [TransportWantedEventData] = []
    /// The given `tlsServerName`; `nil` means the address's host.
    private let givenTlsServerName: String?
    /// Transports `transportFailed` named during the poll; `signallingQueue`.
    private var streamsLetGo: [UInt32] = []
    /// The poll retired the main TCP/TLS transport (keep-alives unanswered,
    /// RFC 5626 §4.4.1) while its socket is still open here; it must be
    /// replaced. Guarded by `signallingQueue`.
    private var mainLetGo = false
    /// Running recording sessions by handle; `callsQueue`.
    private var recordings: [SipralHandle: (call: Call, link: UInt32?)] = [:]

    /// Live accounts, for `networkChanged(to:)` to repoint.
    private var accounts: [SipralHandle: Account] = [:]

    /// Accounts move before any call is re-offered, so each re-INVITE carries
    /// the new `Contact`. Also guards `accounts`.
    private let movingQueue = DispatchQueue(label: "org.sipral.stack.moving")
    /// The network the stack was last told it is on, guarded by `stateQueue`.
    private var network: Network

    private let callsQueue = DispatchQueue(label: "org.sipral.stack.calls")
    private var calls: [SipralHandle: Call] = [:]
    private let box: StackBox
    private let closedSemaphore = DispatchSemaphore(value: 0)
    private let stateQueue = DispatchQueue(label: "org.sipral.stack.state")
    private var closed = false

    // Poll-loop scratch buffers, allocated once and freed in `close()`.
    private let transmitData: UnsafeMutablePointer<UInt8>
    private let transmitDestination: UnsafeMutablePointer<CChar>
    private let farewellData: UnsafeMutablePointer<UInt8>

    /// Weak back-reference for the C callback's `event_user_data`. Filled in
    /// once `self` exists, which is before the poll thread starts, so no
    /// event sees it empty.
    final class StackBox {
        weak var stack: SipralStack?
        /// Where `setLog` sends lines. Guarded by `logQueue`.
        var logHandler: LogHandler?
        let logQueue = DispatchQueue(label: "org.sipral.stack.log")
    }

    /// Receives level, module, the redacted line, and how many lines a flood
    /// dropped before it.
    public typealias LogHandler = @Sendable (SipralLogLevel, String, String, UInt64) -> Void

    /// The STUN server in use, `host:port`, or `nil` for none; the first of
    /// what `setStunServers(_:)` last named.
    public var stunServer: String? { natQueue.sync { currentStunServer } }
    /// What `stunServer` answers. Guarded by `natQueue`.
    private var currentStunServer: String?
    private let turnServer: String?
    private let turn: TurnServer?

    /// TURN-over-TCP/TLS connections by media socket. Guarded by `natQueue`.
    private var turnConnections: [String: TurnConnection] = [:]
    /// Media sockets kept while their TURN connection stands: the Refresh
    /// that releases the relay can come after the `Call` is gone. Guarded by
    /// `natQueue`.
    private var turnSockets: [SipralHandle: String] = [:]
    /// `turnStream` requests, acted on after the poll: nothing may call back
    /// into the stack from inside its callback.
    private var turnAsked: [TurnStreamEventData] = []

    /// Media sockets mapped before their call has a media handle; the poll
    /// thread carries their STUN traffic. `natQueue` also covers each close,
    /// so the poll thread never writes to a released socket.
    private let natQueue = DispatchQueue(label: "org.sipral.stack.nat")
    private var stunSockets: [String: UDPSocket] = [:]
    private var natWaiters: [String: NatWaiter] = [:]

    /// One media socket's wait for `SipralEventKind.natMapping` and, with a
    /// TURN server, `SipralEventKind.natRelay`.
    private final class NatWaiter {
        let done = DispatchSemaphore(value: 0)
        var mapped = false
        /// Where the STUN server saw the socket from.
        var publicAddress: String?
        var relayed: Bool
        init(needsRelay: Bool) { relayed = !needsRelay }
    }

    /// A stack.
    ///
    /// Every option left `nil` takes this build's default. `ice` is what
    /// every call does about ICE (RFC 8445) unless `placeCall(ice:)` says
    /// otherwise; `SipralIce.off` by default. `SipralIce.lite` is only for a
    /// server reachable at the address it advertises (`docs/06-nat.md`).
    ///
    /// `stunServer` (`host:port`, an address, not a name) turns on
    /// `SIPRAL_NAT_STUN`: accounts' `Contact` and every media socket move to
    /// the public address the server reports (`SipralEventKind.natMapping`),
    /// so the SDP names an address the far end can reach. `turn` adds a relay
    /// for each media socket, offered as the relayed ICE candidate; it needs
    /// `stunServer`, and is only used under ICE. `TurnServer.transport`
    /// reaches it over TCP or TLS. `g729AnnexB` allows G.729 silence
    /// compression (on by default).
    ///
    /// `referrals: true` hands an out-of-dialog REFER (click-to-dial) to the
    /// application as `SipralEventKind.referral`, for `acceptReferral` or
    /// `rejectReferral`. Off by default, when each is refused 403: a peer
    /// that can make a phone dial is a toll-fraud vector.
    ///
    /// `registrarKeepalive` (on by default) sends a double CRLF every
    /// `registrarKeepaliveMs` (zero for 25 s, 1 000 to 120 000) from every
    /// account STUN showed to be behind a NAT, so the registrar's INVITE
    /// still gets in. An interval with it off is refused. Nothing is sent
    /// while suspended.
    ///
    /// `audio` says who runs the audio; `.application` means the application
    /// pumps frames. With `.device(activation: .manual)` the devices open
    /// only between `AudioDevices.activate()` and `deactivate()` (CallKit's
    /// `didActivate`/`didDeactivate`). `audioProbeMs` bounds a blocking
    /// device call before `.deviceTimedOut` (zero for 3 s);
    /// `audioDeviceRateHz` is the device rate (zero for 48 000), resampled
    /// to each call's rate.
    ///
    /// `maxDialogs` (zero for 128): an incoming call past it is answered
    /// 503, an outgoing one throws `.limitReached`. `maxServerTransactions`
    /// (zero for 256) bounds requests in progress from other ends.
    /// `diagnosticDecisions` (zero for 64 per call) and `diagnosticRecords`
    /// (zero for 32 calls) bound the diagnostic record.
    ///
    /// `network` is the network the stack starts on, which the first
    /// `networkChanged(to:)` compares with.
    ///
    /// `stunFallbacks` are tried in order when `stunServer` gives no address
    /// within 5.5 s. A failed server is skipped for 30 s, doubling per
    /// failure up to ten minutes; `SipralEventKind.stunServer` reports moves
    /// and total failure.
    ///
    /// `rtpPortMin`/`rtpPortMax` restrict media sockets to a firewall's
    /// range: even ports reserved with `sipral_stack_rtp_port_reserve`, the
    /// odd one above kept for RTCP (RFC 3550 §11). Both zero (default) leave
    /// ports to the OS. When every pair is taken, `.exhausted` is thrown.
    ///
    /// `dtmfDetection`: `.auto` listens for in-band digits on calls that
    /// negotiated no telephone event, or `.always`/`.off`;
    /// `Call.setDtmfDetection` overrides it per call.
    ///
    /// `signalling` is `.udp` (default) on a socket at `bindHost`, or `.tcp`
    /// or `.tls` on one connection to `signallingServer` (`host:port`,
    /// registrar or outbound proxy) shared by every account and call. TLS
    /// needs Network.framework (`.notSupported` elsewhere) and checks the
    /// certificate against `tlsServerName` (default: the host of
    /// `signallingServer`) with `tlsTrust` (`docs/22-tls.md`). The check
    /// cannot be turned off.
    ///
    /// The first connection is made before this returns. On failure or loss
    /// the stack raises `SipralEventKind.transportFailed`, whose
    /// `transportFailedData` gives the reason with Security's own words, and
    /// reconnects after 1 s, doubling up to 30 s. Once back, accounts move to
    /// the new connection and re-register if they were registering. A
    /// `register()` meanwhile waits for it; a call placed meanwhile throws
    /// `.transportDown`.
    ///
    /// `inviteLimit` is how fast one address may ring this stack:
    /// `.standard` (ten at once, then one every 2 s, else 480) or
    /// `.voiceAgent` for a trunk-fed service.
    ///
    /// `streamFallback` (on by default) handles a UDP request too large for
    /// a datagram, usually an `Authorization` answer offering two SRTP suites
    /// (RFC 3261 §18.1.1, 1300 bytes): `transportWanted` is answered with a
    /// TCP connection to the same address and port, bound with
    /// `sipral_stack_transport_bind`, and the request goes on it. If the
    /// connection fails, or with `false`, the stack is told at once
    /// (`transportFailedData.detail` names destination and reason) and the
    /// waiting call ends as unreachable, `endCause` SIP 513. `streamServer`
    /// (`host:port`) redirects that connection, for a server whose TCP port
    /// differs from its UDP port.
    ///
    /// `bindHost` is the signalling address. Left `nil`, the socket listens
    /// on every interface and advertises the route toward the first
    /// account's server (`sipral_advertised_address`); each account and, with
    /// no `mediaHost`, each media socket uses the route toward its own peer.
    /// A loopback address is never advertised to a remote peer
    /// (`.unreachableAddress`).
    ///
    /// `srtp: .bestEffort` offers SDES on plain `RTP/AVP`, for a PBX that
    /// answers `RTP/SAVP` with 488. `srtpSuites` are offered and accepted
    /// unless an account names its own, most preferred first, by their
    /// RFC 4568 and RFC 7714 names.
    ///
    /// `pathMtu` (zero for unknown, else at least 576): requests within
    /// 200 bytes of it move to a stream (RFC 3261 §18.1.1).
    /// `datagramWithoutStreamBytes` deliberately deviates for UDP-only
    /// servers: when no stream can be had, requests up to this size still go
    /// over UDP (zero for never, at most 65 507), reported as
    /// `transport.kept.datagram` in `diagnosticsJson()`.
    ///
    /// `pseudonymSalt` (16 bytes or more) keys the pseudonyms in the log and
    /// `state()`, so traces from two runs compare; keep it secret.
    /// `diagnosticTrace` logs whole SIP messages at trace level with
    /// credentials and keys removed; `setDiagnosticTrace(_:)` toggles it.
    ///
    /// `heldAudio` is what a held party hears: `.default` and `.silence` send
    /// silence (in application mode the frames may be a microphone's);
    /// `.application` sends the application's frames, such as hold music.
    ///
    /// `resolver` answers `SipralEventKind.lookupWanted` for accounts added
    /// with `serverUri`, one thread per lookup; `nil` means
    /// `SipralDns.platform` (system SRV/NAPTR, `getaddrinfo`).
    public init(
        audio: AudioMode = .platformDefault,
        bindHost: String? = nil,
        bindPort: UInt16 = 0,
        userAgent: String? = nil,
        codecs: String? = nil,
        frameMs: UInt32 = 0,
        offerDtmf: Bool? = nil,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil,
        stunServer: String? = nil,
        turn: TurnServer? = nil,
        g729AnnexB: Bool? = nil,
        referrals: Bool? = nil,
        registrarKeepalive: Bool? = nil,
        registrarKeepaliveMs: UInt64 = 0,
        audioProbeMs: UInt64 = 0,
        audioDeviceRateHz: UInt32 = 0,
        maxDialogs: UInt32 = 0,
        maxServerTransactions: UInt32 = 0,
        diagnosticDecisions: UInt32 = 0,
        diagnosticRecords: UInt32 = 0,
        rtpPortMin: UInt16 = 0,
        rtpPortMax: UInt16 = 0,
        network: Network? = nil,
        stunFallbacks: [String] = [],
        dtmfDetection: SipralDtmfDetection = .auto,
        signalling: SipralTransport = .udp,
        signallingServer: String? = nil,
        tlsServerName: String? = nil,
        tlsTrust: TLSTrust = .platform,
        inviteLimit: InviteLimit? = nil,
        streamFallback: Bool = true,
        streamServer: String? = nil,
        srtpSuites: [String] = [],
        pathMtu: UInt32 = 0,
        datagramWithoutStreamBytes: UInt32 = 0,
        pseudonymSalt: [UInt8]? = nil,
        diagnosticTrace: Bool? = nil,
        systemEchoCancellation: Bool? = nil,
        heldAudio: SipralHeldAudio = .default,
        resolver: SipralResolver? = nil
    ) throws {
        self.streamFallback = streamFallback
        self.streamServer = streamServer
        self.rtpPorts = rtpPortMin == 0 && rtpPortMax == 0 ? nil : (rtpPortMin, rtpPortMax)
        guard signalling == .udp || signalling == .tcp || signalling == .tls else {
            throw SipralError(status: .invalidArgument, message: "signalling is .udp, .tcp or .tls")
        }
        let streamed = signalling != .udp
        if streamed && signallingServer == nil {
            throw SipralError(status: .invalidArgument, message: "SIP over TCP or TLS needs signallingServer, host:port")
        }
        self.signalling = signalling
        self.signallingServer = signallingServer
        self.givenTlsServerName = tlsServerName
        self.tlsServerName = tlsServerName ?? signallingServer.map { UDPSocket.parse($0).host } ?? bindHost ?? ""
        self.tlsTrust = tlsTrust
        self.linkHost = bindHost
        self.chosenPort = bindPort
        self.routes = bindHost == nil
        self.routeChosen = bindHost != nil || streamed || streamServer != nil
        self.resolver = resolver ?? SipralDns.platform
        var firstLink: SignallingConnection?
        var firstRefusal: SignallingRefusal?
        let socket: UDPSocket?
        let bound: String
        if streamed {
            socket = nil
            do {
                let made = try SignallingConnection(
                    server: signallingServer!, bindHost: bindHost, transport: signalling,
                    serverName: self.tlsServerName, trust: tlsTrust, patienceMs: Self.patienceMs
                )
                firstLink = made
                bound = made.local
            } catch let refusal as SignallingRefusal {
                firstRefusal = refusal
                bound = "\(bindHost ?? Self.routeHost(toward: signallingServer)):\(bindPort)"
            }
        } else {
            let made = try UDPSocket(host: bindHost ?? "0.0.0.0", port: bindPort)
            socket = made
            bound = bindHost != nil
                ? made.localAddress
                : "\(Self.routeHost(toward: streamServer)):\(UDPSocket.parse(made.localAddress).port)"
            if bindHost == nil {
                advertisedLocal = bound
            }
        }
        self.socket = socket
        self.linkLocal = bound
        self.audioMode = audio
        self.network = network ?? Network(link: .wired, address: bindHost ?? UDPSocket.parse(bound).host)
        self.currentStunServer = stunServer
        self.turnServer = turn?.address
        self.turn = turn
        self.origin = .now()
        self.box = StackBox()
        self.transmitData = .allocate(capacity: 65536)
        self.transmitDestination = .allocate(capacity: 128)
        self.farewellData = .allocate(capacity: 1500)

        var rng = SystemRandomNumberGenerator()
        let entropy = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let mediaSeed = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let boxPointer = Unmanaged.passUnretained(box).toOpaque()

        self.handle = try entropy.withUnsafeBufferPointer { entropyBuf in
            try mediaSeed.withUnsafeBufferPointer { seedBuf in
                try CStrings.with(
                    [
                        bound, userAgent, codecs, stunServer, turn?.address, turn?.username,
                        turn?.password, stunFallbacks.isEmpty ? nil : stunFallbacks.joined(separator: ","),
                        srtpSuites.isEmpty ? nil : srtpSuites.joined(separator: ","),
                    ]
                ) { parts in
                    var config = sipral_stack_config_t.sized()
                    config.event_callback = sipralStackEventTrampoline
                    config.event_user_data = boxPointer
                    config.transport = signalling.rawValue
                    config.bind_address = parts[0].pointer
                    config.bind_address_len = parts[0].count
                    config.user_agent = parts[1].pointer
                    config.user_agent_len = parts[1].count
                    config.entropy = entropyBuf.baseAddress
                    config.entropy_len = 32
                    config.codecs = parts[2].pointer
                    config.codecs_len = parts[2].count
                    config.frame_ms = frameMs
                    config.offer_dtmf = SipralStack.toggle(offerDtmf)
                    config.media_clock_unix_seconds = SipralStack.unixSeconds()
                    config.media_seed = seedBuf.baseAddress
                    config.media_seed_len = 32
                    config.srtp = srtp?.rawValue ?? 0
                    config.ice = ice?.rawValue ?? 0
                    config.g729_annex_b = SipralStack.toggle(g729AnnexB)
                    config.referrals = SipralStack.toggle(referrals)
                    config.registrar_keepalive = SipralStack.toggle(registrarKeepalive)
                    config.registrar_keepalive_ms = registrarKeepaliveMs
                    let (mode, activation) = audio.raw
                    config.audio = mode
                    config.audio_activation = activation
                    config.audio_probe_ms = audioProbeMs
                    config.audio_device_rate_hz = audioDeviceRateHz
                    config.max_dialogs = maxDialogs
                    config.max_server_transactions = maxServerTransactions
                    config.diagnostic_decisions = diagnosticDecisions
                    config.diagnostic_records = diagnosticRecords
                    config.rtp_port_min = UInt32(rtpPortMin)
                    config.rtp_port_max = UInt32(rtpPortMax)
                    config.dtmf_detection = dtmfDetection.rawValue
                    if audio.isDevice {
                        config.audio_transmit_callback = sipralAudioTransmitTrampoline
                        config.audio_transmit_user_data = boxPointer
                    }
                    if let stunPointer = parts[3].pointer {
                        config.nat = SipralNat.stun.rawValue
                        config.stun_server = stunPointer
                        config.stun_server_len = parts[3].count
                    }
                    if let fallbacksPointer = parts[7].pointer {
                        config.stun_fallbacks = fallbacksPointer
                        config.stun_fallbacks_len = parts[7].count
                    }
                    if let turnPointer = parts[4].pointer {
                        config.turn_server = turnPointer
                        config.turn_server_len = parts[4].count
                        config.turn_username = parts[5].pointer
                        config.turn_username_len = parts[5].count
                        config.turn_password = parts[6].pointer
                        config.turn_password_len = parts[6].count
                        config.turn_transport = turn?.transport.rawValue ?? 0
                    }
                    if let suitesPointer = parts[8].pointer {
                        config.srtp_suites = suitesPointer
                        config.srtp_suites_len = parts[8].count
                    }
                    config.path_mtu = pathMtu
                    config.datagram_without_stream_bytes = datagramWithoutStreamBytes
                    config.diagnostic_trace = SipralStack.toggle(diagnosticTrace)
                    config.system_echo_cancellation = SipralStack.toggle(systemEchoCancellation)
                    config.held_audio = heldAudio.rawValue
                    let salt = pseudonymSalt ?? []
                    return try salt.withUnsafeBufferPointer { saltBytes in
                        if !saltBytes.isEmpty {
                            config.pseudonym_salt = saltBytes.baseAddress
                            config.pseudonym_salt_len = saltBytes.count
                        }
                        return try Sipral.stackCreate(config: config)
                    }
                }
            }
        }

        box.stack = self
        if audio.isDevice {
            self.audio = AudioDevices(stack: self)
        }
        if let inviteLimit {
            try Sipral.stackInviteLimit(stack: handle, everyMs: inviteLimit.everyMs, burst: inviteLimit.burst)
        }
        if let firstLink {
            try install(firstLink)
        } else if let firstRefusal {
            report(firstRefusal)
            reconnectLater()
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.run() }
    }

    // MARK: - SIP over TCP or TLS

    /// One connection attempt, TLS handshake included.
    private static let patienceMs = 5000

    /// The `Contact` transport parameter (RFC 3261 §19.1.1); empty over UDP.
    var contactParameters: String {
        switch signalling {
        case .tls: return ";transport=tls"
        case .tcp: return ";transport=tcp"
        default: return ""
        }
    }

    /// Bind an open connection and start reading it.
    private func install(_ made: SignallingConnection) throws {
        do {
            _ = try retryingBusy {
                try Sipral.stackTransportBind(
                    stack: handle, transport: Sipral.transportMain, protocol: signalling.rawValue,
                    local: made.local, remote: made.remote, nowMs: nowMs()
                )
            }
        } catch {
            made.close()
            throw error
        }
        signallingQueue.sync {
            link = made
            linkLocal = made.local
        }
        made.start(
            bytes: { [weak self] bytes in self?.linkReceived(made, bytes) },
            lost: { [weak self] refusal in self?.lose(made, refusal, tell: true) }
        )
    }

    /// `sipral_stack_transport_failed_with`, never throwing on the way out.
    private func report(_ refusal: SignallingRefusal) {
        let detail = refusal.detail
        detail.withCString { text in
            var failure = sipral_transport_failure_t.sized()
            failure.transport = Sipral.transportMain
            failure.error = refusal.error.rawValue
            failure.tls = signalling == .tls ? refusal.tls.rawValue : SipralTlsFailure.none.rawValue
            failure.detail = detail.isEmpty ? nil : text
            failure.detail_len = detail.utf8.count
            _ = try? retryingBusy { try Sipral.stackTransportFailedWith(stack: handle, failure: failure, nowMs: nowMs()) }
        }
    }

    /// Feeds every byte in order: a busy stack is waited for, not skipped.
    private func linkReceived(_ made: SignallingConnection, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackReceiveStream(stack: handle, transport: Sipral.transportMain, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy || error.status == .clockBehind {
                usleep(1000)
            } catch {
                // the framing is lost: the stack retired the transport and
                // said so itself
                lose(made, nil, tell: false)
                return
            }
        }
    }

    /// Close `made` if it is still current, tell the stack (orderly close
    /// when `refusal` is nil, failure otherwise, nothing unless `tell`) and
    /// reconnect.
    private func lose(_ made: SignallingConnection, _ refusal: SignallingRefusal?, tell: Bool) {
        let current = signallingQueue.sync { () -> Bool in
            guard link === made else { return false }
            link = nil
            return true
        }
        guard current else { return }
        made.close()
        guard !isClosed else { return }
        if tell, let refusal {
            report(refusal)
        } else if tell {
            _ = try? retryingBusy {
                try Sipral.stackStreamClosed(stack: handle, transport: Sipral.transportMain, nowMs: nowMs())
            }
        }
        reconnectLater()
    }

    /// The stack retired the connection itself; close it and reconnect
    /// without telling it again.
    private func actOnMainLetGo() {
        let made = signallingQueue.sync { () -> SignallingConnection? in
            guard mainLetGo else { return nil }
            mainLetGo = false
            return link
        }
        if let made {
            lose(made, nil, tell: false)
        }
    }

    /// Start connecting again, unless that is already under way.
    private func reconnectLater() {
        let start = stateQueue.sync { () -> Bool in
            guard !closed, !reconnecting else { return false }
            reconnecting = true
            return true
        }
        guard start else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.reconnect() }
    }

    private func reconnect() {
        var delayMs = 1000
        defer { stateQueue.sync { reconnecting = false } }
        while !isClosed {
            usleep(useconds_t(delayMs) * 1000)
            delayMs = min(delayMs * 2, 30000)
            guard !isClosed, let server = signallingServer else { return }
            let made: SignallingConnection
            do {
                made = try SignallingConnection(
                    server: server, bindHost: signallingQueue.sync { linkHost }, transport: signalling,
                    serverName: tlsServerName, trust: tlsTrust, patienceMs: Self.patienceMs
                )
            } catch let refusal as SignallingRefusal {
                report(refusal)
                continue
            } catch {
                return
            }
            guard !isClosed else {
                made.close()
                return
            }
            guard (try? install(made)) != nil else { continue }
            afterReconnect()
            return
        }
    }

    // MARK: - connections to recording servers

    /// Clear of `Sipral.transportMain` and of the small ids an application
    /// driving the C layer would pick; the ABI leaves the choice to us.
    static let firstLink: UInt32 = 64

    /// Skips ids still held. Called on `signallingQueue`.
    private func takeLinkId() -> UInt32 {
        while recordingLinks[nextLink] != nil || streamLinks[nextLink] != nil || nextLink == Sipral.transportMain {
            nextLink &+= 1
        }
        defer { nextLink &+= 1 }
        return nextLink
    }

    /// TCP to a recording server, bound as its own transport: the recording
    /// INVITE exceeds RFC 3261 §18.1.1's UDP limit. `.transportDown` when
    /// refused.
    func openRecordingLink(to destination: String) throws -> UInt32 {
        let made: SignallingConnection
        do {
            made = try SignallingConnection(
                server: destination, bindHost: signallingQueue.sync { linkHost }, transport: .tcp,
                serverName: UDPSocket.parse(destination).host, trust: .platform, patienceMs: Self.patienceMs
            )
        } catch let refusal as SignallingRefusal {
            throw SipralError(status: .transportDown, message: "the recording server \(destination): \(refusal.detail)")
        }
        let id = signallingQueue.sync { takeLinkId() }
        do {
            _ = try retryingBusy {
                try Sipral.stackTransportBind(
                    stack: handle, transport: id, protocol: SipralTransport.tcp.rawValue,
                    local: made.local, remote: made.remote, nowMs: nowMs()
                )
            }
        } catch {
            made.close()
            throw error
        }
        signallingQueue.sync { recordingLinks[id] = made }
        made.start(
            bytes: { [weak self] bytes in self?.recordingReceived(id, bytes) },
            lost: { [weak self] refusal in self?.recordingLinkLost(id, refusal) }
        )
        return id
    }

    /// Close and unbind a recording-server connection.
    func closeRecordingLink(_ id: UInt32) {
        let open = signallingQueue.sync { recordingLinks.removeValue(forKey: id) }
        guard let open else { return }
        open.close()
        _ = try? retryingBusy { try Sipral.stackStreamClosed(stack: handle, transport: id, nowMs: nowMs()) }
    }

    private func recordingReceived(_ id: UInt32, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackReceiveStream(stack: handle, transport: id, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy || error.status == .clockBehind {
                usleep(1000)
            } catch {
                closeRecordingLink(id)
                return
            }
        }
    }

    private func recordingLinkLost(_ id: UInt32, _ refusal: SignallingRefusal?) {
        let open = signallingQueue.sync { recordingLinks.removeValue(forKey: id) }
        guard open != nil, !isClosed else { return }
        if let refusal {
            let detail = refusal.detail
            detail.withCString { text in
                var failure = sipral_transport_failure_t.sized()
                failure.transport = id
                failure.error = refusal.error.rawValue
                failure.detail = detail.isEmpty ? nil : text
                failure.detail_len = detail.utf8.count
                _ = try? retryingBusy { try Sipral.stackTransportFailedWith(stack: handle, failure: failure, nowMs: nowMs()) }
            }
        } else {
            _ = try? retryingBusy { try Sipral.stackStreamClosed(stack: handle, transport: id, nowMs: nowMs()) }
        }
    }

    // MARK: - RFC 3261 §18.1.1: a request too large for a datagram

    /// The stack retires a connection that stopped answering keep-alives
    /// (RFC 5626 §4.4.1) while its socket is still open here; left open, it
    /// would stand in for the replacement the stack asks for.
    func noteStreamLetGo(_ id: UInt32) {
        signallingQueue.sync { streamsLetGo.append(id) }
    }

    /// Answer `transportWanted` after the poll: open each missing connection
    /// off the poll thread, or with `streamFallback` off, say none is coming.
    private func actOnStreamsWanted() {
        let letGo = signallingQueue.sync { () -> [UInt32] in
            defer { streamsLetGo = [] }
            return streamsLetGo
        }
        for id in letGo {
            loseStreamLink(id, tell: false)
        }
        let asked = signallingQueue.sync { () -> [TransportWantedEventData] in
            defer { streamsAsked = [] }
            return streamsAsked
        }
        var seen: Set<String> = []
        for wanted in asked where seen.insert(wanted.destination).inserted {
            let destination = wanted.destination
            // An account's own connection is opened whatever
            // `streamFallback` says.
            let opens = streamFallback || (wanted.requestBytes == 0 && wanted.limitBytes == 0)
            let id = signallingQueue.sync { () -> UInt32? in
                if streamsOpening.contains(destination)
                    || streamLinks.values.contains(where: { $0.destination == destination }) {
                    return nil
                }
                if opens {
                    streamsOpening.insert(destination)
                }
                return takeLinkId()
            }
            guard let id else { continue }
            guard opens else {
                sayNoStream(id, .connectionRefused, "to \(destination) not tried: streamFallback is off")
                continue
            }
            let over: SipralTransport = wanted.protocolRaw == SipralTransport.tls.rawValue ? .tls : .tcp
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.openStreamLink(id, to: destination, over: over)
            }
        }
    }

    /// The account's pin for that server if it has one, else `tlsTrust`.
    private func streamTrust(to destination: String) -> TLSTrust {
        let pinned = movingQueue.sync {
            accounts.values.first { $0.streamProtocol == .tls && $0.registrarAddress == destination && $0.tlsPin != nil }
        }
        if let pin = pinned?.tlsPin, let trust = try? TLSTrust.pinned(pin) {
            return trust
        }
        return tlsTrust
    }

    /// Connect (TCP, or TLS for such an account) to `destination` or to
    /// `streamServer`, and bind it under `id`. A failure is reported under
    /// the same id, which ends whatever waited for it.
    private func openStreamLink(_ id: UInt32, to destination: String, over: SipralTransport = .tcp) {
        let made: SignallingConnection
        let server = over == .tcp ? streamServer ?? destination : destination
        do {
            made = try SignallingConnection(
                server: server, bindHost: signallingQueue.sync { linkHost }, transport: over,
                serverName: over == .tls ? givenTlsServerName ?? UDPSocket.parse(server).host : UDPSocket.parse(server).host,
                trust: over == .tls ? streamTrust(to: destination) : .platform, patienceMs: Self.patienceMs
            )
        } catch {
            signallingQueue.sync { _ = streamsOpening.remove(destination) }
            let refusal = error as? SignallingRefusal
            let kind = refusal?.error ?? .other
            let target = server == destination ? destination : "\(server) (for \(destination))"
            let said = refusal?.detail ?? "\(error)"
            sayNoStream(
                id, kind, "to \(target) \(Self.verdict(kind))\(said.isEmpty ? "" : ": \(said)")", over: over,
                tls: over == .tls ? refusal?.tls ?? SipralTlsFailure.none : SipralTlsFailure.none
            )
            return
        }
        let closing = isClosed
        signallingQueue.sync {
            streamsOpening.remove(destination)
            if !closing {
                streamLinks[id] = (destination, made)
            }
        }
        guard !closing else {
            made.close()
            return
        }
        do {
            _ = try retryingBusy {
                try Sipral.stackTransportBind(
                    stack: handle, transport: id, protocol: over.rawValue,
                    local: made.local, remote: destination, nowMs: nowMs()
                )
            }
        } catch {
            loseStreamLink(id, tell: false)
            sayNoStream(id, .other, "to \(destination) connected, and the stack would not bind it: \(error)")
            return
        }
        made.start(
            bytes: { [weak self] bytes in self?.streamReceived(id, bytes) },
            lost: { [weak self] _ in self?.loseStreamLink(id, tell: true) }
        )
    }

    /// Never throws. `what` follows the protocol name in
    /// `transportFailedData.detail`: destination and outcome.
    private func sayNoStream(
        _ id: UInt32, _ error: SipralTransportError, _ what: String, over: SipralTransport = .tcp,
        tls: SipralTlsFailure = SipralTlsFailure.none
    ) {
        let detail = SignallingRefusal.sentence("\(over == .tls ? "TLS" : "TCP") \(what)")
        detail.withCString { text in
            var failure = sipral_transport_failure_t.sized()
            failure.transport = id
            failure.error = error.rawValue
            failure.tls = tls.rawValue
            failure.detail = text
            failure.detail_len = detail.utf8.count
            _ = try? retryingBusy { try Sipral.stackTransportFailedWith(stack: handle, failure: failure, nowMs: nowMs()) }
        }
    }

    /// What became of a connection, in the words a log line reads.
    private static func verdict(_ error: SipralTransportError) -> String {
        switch error {
        case .connectionRefused: return "refused"
        case .timedOut: return "timed out"
        case .unreachable: return "unreachable"
        case .connectionReset: return "reset"
        case .closed: return "closed"
        default: return "failed"
        }
    }

    /// Feeds every byte in order to `sipral_stack_receive_stream`.
    private func streamReceived(_ id: UInt32, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackReceiveStream(stack: handle, transport: id, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy || error.status == .clockBehind {
                usleep(1000)
            } catch {
                // the framing is lost: the stack retired the transport itself
                loseStreamLink(id, tell: false)
                return
            }
        }
    }

    /// Close `id`; `tell` also reports it with `sipral_stack_stream_closed`.
    private func loseStreamLink(_ id: UInt32, tell: Bool) {
        let open = signallingQueue.sync { streamLinks.removeValue(forKey: id) }
        guard let open else { return }
        open.link.close()
        guard tell, !isClosed else { return }
        _ = try? retryingBusy { try Sipral.stackStreamClosed(stack: handle, transport: id, nowMs: nowMs()) }
    }

    /// A recording session is running for `call`, over `link` when it has a
    /// connection of its own.
    func recordingStarted(_ recording: SipralHandle, of call: Call, link: UInt32?) {
        callsQueue.sync { recordings[recording] = (call, link) }
    }

    /// The connection closes a second later, once the answer to the
    /// server's BYE has left.
    private func recordingEnded(_ recording: SipralHandle) {
        let ended = callsQueue.sync { recordings.removeValue(forKey: recording) }
        guard let ended else { return }
        ended.call.recordingEnded()
        if let link = ended.link {
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) { [weak self] in
                self?.closeRecordingLink(link)
            }
        }
    }

    /// Accounts move to the new connection's address (one with its own
    /// `Contact` keeps it) and re-register now rather than at the next
    /// back-off.
    private func afterReconnect() {
        let all = movingQueue.sync { Array(accounts.values) }
        let local = bindAddress
        for account in all {
            try? account.rebind(local: local, previous: nil)
            if account.wantsRegistration {
                try? account.register()
            }
        }
    }

    deinit {
        transmitData.deallocate()
        transmitDestination.deallocate()
        farewellData.deallocate()
    }

    private static func toggle(_ value: Bool?) -> UInt32 {
        guard let value else { return SipralToggle.default.rawValue }
        return value ? SipralToggle.on.rawValue : SipralToggle.off.rawValue
    }

    private static func unixSeconds() -> UInt64 {
        var ts = timespec()
        clock_gettime(CLOCK_REALTIME, &ts)
        return UInt64(ts.tv_sec)
    }

    /// The RTP port range media sockets are bound in, or `nil` when the
    /// operating system picks.
    public let rtpPorts: (min: UInt16, max: UInt16)?

    /// A media socket at `host`: at `port` if named, else at an even port
    /// from the RTP range (one another process holds is released and the
    /// next tried), else the OS's choice. `.exhausted` once every pair is
    /// taken.
    public func openMediaSocket(host: String, port: UInt16 = 0) throws -> UDPSocket {
        guard port == 0, let range = rtpPorts else {
            return try UDPSocket(host: host, port: port)
        }
        var failure: Error?
        for _ in 0..<max(1, (Int(range.max) - Int(range.min) + 1) / 2) {
            let reserved = try retryingBusy { try Sipral.stackRtpPortReserve(stack: handle) }
            do {
                return try UDPSocket(host: host, port: UInt16(reserved))
            } catch {
                giveBackPort(UInt16(reserved))
                failure = error
            }
        }
        throw failure ?? SipralError(status: .exhausted, message: "no RTP port could be bound")
    }

    /// Best effort: a port a call took is released when the call ends.
    func giveBackPort(_ port: UInt16) {
        guard rtpPorts != nil else { return }
        try? retryingBusy { try Sipral.stackRtpPortRelease(stack: handle, port: UInt32(port)) }
    }

    /// Send this stack's log at `level` and louder to `handler`; `.off` or a
    /// `nil` handler turns it off. The handler runs on whichever thread just
    /// left the stack (usually the poll thread), outside its lock, so it may
    /// call back in. Lines are already redacted.
    public func setLog(level: SipralLogLevel, handler: LogHandler?) throws {
        let box = self.box
        box.logQueue.sync { box.logHandler = level == .off ? nil : handler }
        let on = level != .off && handler != nil
        let boxPointer = Unmanaged.passUnretained(box).toOpaque()
        // Two calls rather than a conditional over the callback: Swift 6.4
        // forms a C function pointer only from a direct function reference.
        try retryingBusy {
            if on {
                try Sipral.check(
                    sipral_stack_log(handle, level.rawValue, sipralLogTrampoline, boxPointer)
                )
            } else {
                try Sipral.check(
                    sipral_stack_log(handle, SipralLogLevel.off.rawValue, nil, nil)
                )
            }
        }
    }

    /// The redacted state dump for a crash report
    /// (`sipral_stack_state_text`). Safe from any thread; never waits.
    public func state() throws -> String {
        var buffer = [CChar](repeating: 0, count: Sipral.stateTextMax)
        let length = try Sipral.stackStateText(stack: handle, buffer: &buffer)
        let bytes = buffer.prefix(max(0, length - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    #if canImport(os)
    /// Send this stack's log to the unified logging system, one `os.Logger`
    /// per target under `subsystem` (categories in
    /// `docs/17-observability.md`). Levels map through
    /// `SipralLogLevel.osLogType`. Lines are redacted by the stack, so they
    /// are logged as public. Replaces any `setLog(level:handler:)` handler.
    public func logTo(subsystem: String = "org.sipral", level: SipralLogLevel = .info) throws {
        let loggers = OSLoggers(subsystem: subsystem)
        try setLog(level: level) { line, target, message, suppressed in
            let logger = loggers.logger(for: target)
            if suppressed == 0 {
                logger.log(level: line.osLogType, "\(message, privacy: .public)")
            } else {
                logger.log(
                    level: line.osLogType,
                    "\(message, privacy: .public) (\(suppressed, privacy: .public) lines turned away before this one)"
                )
            }
        }
    }
    #endif

    /// Health counters since creation (`sipral_stack_counters`). One struct
    /// copy, cheap enough to sample on a timer.
    public func counters() throws -> SipralCounters {
        SipralCounters(try retryingBusy { try Sipral.stackCounters(stack: handle) })
    }

    /// Replace the STUN servers (`host:port`, in order of preference)
    /// without recreating the stack (`sipral_stack_stun_servers`).
    ///
    /// Mapped sockets are asked again at once (`.stunServer`, then
    /// `.natMapping`). An empty list stops STUN: accounts register their own
    /// address again. A stack with a TURN server needs STUN, so an empty
    /// list there throws `.invalidArgument`, as does a malformed entry.
    public func setStunServers(_ servers: [String]) throws {
        let listed = servers.joined(separator: ",")
        try retryingBusy { try Sipral.stackStunServers(stack: handle, servers: listed, nowMs: nowMs()) }
        natQueue.sync { currentStunServer = servers.first }
    }

    /// `sipral_stack_network_test`: test the network before a call; returns
    /// the test's number, and the result arrives as
    /// `SipralEventKind.networkTest`. `account`'s server gets an `OPTIONS`;
    /// the STUN part reuses the signalling socket's last answer. `echoCall`
    /// (a call to an echo service) is measured for `echoMs` (default 8000)
    /// once media starts, then hung up. A part silent past `timeoutMs`
    /// (default 30000) fails.
    public func networkTest(
        account: Account? = nil,
        echoCall: Call? = nil,
        echoMs: UInt32 = 0,
        timeoutMs: UInt32 = 0
    ) throws -> UInt32 {
        var config = sipral_network_test_config_t.sized()
        config.account = account?.handle ?? Sipral.handleNone
        config.echo_call = echoCall?.handle ?? Sipral.handleNone
        config.echo_ms = echoMs
        config.timeout_ms = timeoutMs
        return try retryingBusy {
            try Sipral.stackNetworkTest(stack: handle, config: config, nowMs: nowMs())
        }
    }

    /// `sipral_stack_stir`: verify incoming callers against `anchors` (PEM
    /// or DER; the STI-PA roots under SHAKEN, RFC 8224), replacing earlier
    /// anchors. `unixSeconds` is the clock PASSporTs are judged by (default:
    /// this machine's). A stack that only signs calls this with no anchors
    /// before adding accounts. The certificate is requested through
    /// `SipralEventKind.callerVerification` and supplied with
    /// `stirCertificate(call:chain:)`. `acceptServiceProviderCodes` lets a
    /// certificate naming a service provider code vouch for any caller, as
    /// under SHAKEN; off, it covers only the numbers it names.
    public func stir(
        anchors: [UInt8]?,
        freshnessSeconds: UInt64 = 0,
        certificateWaitMs: UInt64 = 0,
        unixSeconds: UInt64? = nil,
        acceptServiceProviderCodes: Bool = false
    ) throws {
        let now = unixSeconds ?? UInt64(time(nil))
        let given = anchors ?? []
        try given.withUnsafeBufferPointer { bytes in
            var config = sipral_stir_config_t.sized()
            if !bytes.isEmpty {
                config.anchors = bytes.baseAddress
                config.anchors_len = bytes.count
            }
            config.freshness_seconds = freshnessSeconds
            config.certificate_wait_ms = certificateWaitMs
            config.unix_seconds = now
            config.accept_service_provider_codes = acceptServiceProviderCodes
                ? SipralToggle.on.rawValue : 0
            try retryingBusy { try Sipral.stackStir(stack: handle, config: config, nowMs: nowMs()) }
        }
    }

    /// `sipral_call_stir_certificate`: the fetched chain (PEM or DER, signer
    /// first), or `nil` when unavailable. `call` is the handle the event
    /// named, since the call is not announced yet. The verdict follows as
    /// `callerVerification` at `.verified`.
    public func stirCertificate(call: SipralHandle, chain: [UInt8]?) throws {
        try retryingBusy {
            try Sipral.callStirCertificate(stack: handle, call: call, chain: chain ?? [], nowMs: nowMs())
        }
    }

    /// Milliseconds since creation: the `now_ms` every entry point expects.
    public func nowMs() -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- origin.uptimeNanoseconds) / 1_000_000
    }

    // MARK: - accounts and calls

    /// `sipral_account_add`.
    ///
    /// `sessionTimer` (RFC 4028) defaults to thirty minutes. `privacy`
    /// places calls anonymously (RFC 3323): `[.id]` withholds the number,
    /// `From` becomes anonymous and the real identity goes in
    /// `P-Asserted-Identity` only toward a trusted peer. `trustedPeers` are
    /// the IPs of RFC 3325's trust domain (usually registrar or trunk): only
    /// their asserted identity is read (`CallerIdentity`), and once any are
    /// named no identity field goes to other peers. `security` is the
    /// account's SRTP and STIR/SHAKEN policy (`AccountSecurity`).
    ///
    /// `serverUri` (located by RFC 3263, e.g. `sips:example.com:5061`)
    /// replaces `registrarAddress`; give exactly one, else
    /// `.invalidArgument`. `SipralEventKind.located` and `.locateFailed`
    /// report the lookup. A REGISTER waits for it; a call placed before it
    /// with no `destination` throws `.wrongState`. `serverNaptr` asks NAPTR
    /// before SRV (RFC 3263 §4.1). `keepaliveMs` (1 000 to 120 000, zero for
    /// never) keeps the flow open whatever STUN found. `tlsPin` is the
    /// SHA-256 fingerprint of the one certificate trusted, for an
    /// application running TLS itself
    /// (`Account.checkCertificate(_:unixSeconds:)`).
    ///
    /// `streamProtocol` (`.tcp` or `.tls`) gives the account its own
    /// connection to its server, beside UDP accounts on the same stack; its
    /// REGISTER and calls go over it. TLS checks `tlsPin` if set, else the
    /// stack's `tlsTrust`. A closed connection is reopened; until open, a
    /// call throws `.transportDown`. Only on a UDP stack; other values throw
    /// `.invalidArgument`.
    ///
    /// `realms` are the realms the password answers (RFC 3261 §22.1). Empty
    /// means the server's first realm and those its REGISTERs are challenged
    /// with; an SBC challenging calls under another realm needs both named.
    /// Other challenges go unanswered and raise
    /// `SipralEventKind.challengeDeclined`.
    public func addAccount(
        aor: String,
        registrarAddress: String? = nil,
        serverUri: String? = nil,
        serverNaptr: Bool = false,
        keepaliveMs: UInt64 = 0,
        tlsPin: String? = nil,
        streamProtocol: SipralTransport? = nil,
        registrar: String? = nil,
        contact: String? = nil,
        displayName: String? = nil,
        authUser: String? = nil,
        authPassword: String? = nil,
        expiresSeconds: UInt64 = 0,
        sessionTimer: SessionTimer = .default,
        privacy: Privacy = [],
        trustedPeers: [String] = [],
        realms: [String] = [],
        security: AccountSecurity = AccountSecurity()
    ) throws -> Account {
        guard (registrarAddress == nil) != (serverUri == nil) else {
            throw SipralError(
                status: .invalidArgument,
                message: "an account names its server by registrarAddress or by serverUri, one of the two"
            )
        }
        if let streamProtocol {
            guard streamProtocol == .tcp || streamProtocol == .tls, signalling == .udp else {
                throw SipralError(
                    status: .invalidArgument,
                    message: "streamProtocol is .tcp or .tls, on a stack that signals over UDP"
                )
            }
        }
        var advertised: String?
        if contact == nil, signalling == .udp, let registrarAddress, routes {
            advertised = try advertise(toward: registrarAddress)
        }
        let account = try Account.add(
            stack: self,
            aor: aor,
            registrarAddress: registrarAddress,
            serverUri: serverUri,
            serverNaptr: serverNaptr,
            keepaliveMs: keepaliveMs,
            tlsPin: tlsPin,
            streamProtocol: streamProtocol,
            advertised: advertised,
            registrar: registrar,
            contact: contact,
            displayName: displayName,
            authUser: authUser,
            authPassword: authPassword,
            expiresSeconds: expiresSeconds,
            sessionTimer: sessionTimer,
            privacy: privacy,
            trustedPeers: trustedPeers,
            realms: realms,
            security: security
        )
        movingQueue.sync { accounts[account.handle] = account }
        return account
    }

    /// The route toward `peer` on this stack's port. The first server named
    /// also sets the `Via` address.
    private func advertise(toward peer: String) throws -> String {
        let port = UDPSocket.parse(bindAddress).port
        let address = "\(Self.routeHost(toward: peer)):\(port)"
        let first = signallingQueue.sync { () -> Bool in
            defer { routeChosen = true }
            return !routeChosen
        }
        if first, address != bindAddress {
            try advertiseMain(at: address)
        }
        return address
    }

    /// Rename the UDP transport's `Via` address.
    private func advertiseMain(at address: String) throws {
        try retryingBusy {
            var bound: UInt32 = 0
            let status = address.withCString {
                sipral_stack_transport_bind(
                    handle, Sipral.transportMain, SipralTransport.udp.rawValue, $0, address.utf8.count, nil, 0,
                    nowMs(), &bound
                )
            }
            try Sipral.check(status)
        }
        signallingQueue.sync { advertisedLocal = address }
    }

    /// Re-picked after a move: the route toward the first account's server,
    /// else `address` on the same port. Called with `movingQueue` held.
    private func advertiseAgain(after address: String?) throws -> String {
        signallingQueue.sync { routeChosen = false }
        let servers = accounts.sorted { $0.key < $1.key }.map { $0.value.registrarAddress }
        if let server = servers.first(where: Self.isAddress) {
            return try advertise(toward: server)
        }
        let local = "\(address ?? Self.routeHost(toward: streamServer)):\(UDPSocket.parse(bindAddress).port)"
        if local != bindAddress {
            try advertiseMain(at: local)
        }
        return local
    }

    /// Run each lookup on its own thread (a resolver may take seconds; the
    /// poll thread must not wait), and repoint accounts `.located` moved.
    private func actOnLookups() {
        let (asked, located) = signallingQueue.sync { () -> ([(account: SipralHandle, name: String, record: UInt32)], [(account: SipralHandle, target: String)]) in
            defer {
                lookupsAsked = []
                locatedAsked = []
            }
            return (lookupsAsked, locatedAsked)
        }
        for lookup in asked {
            let resolver = self.resolver
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let answer = SipralDnsRecordType(rawValue: lookup.record).map { resolver(lookup.name, $0) } ?? .nothing
                self?.lookedUp(account: lookup.account, name: lookup.name, record: lookup.record, answer)
            }
        }
        for (handle, target) in located {
            guard let account = movingQueue.sync(execute: { accounts[handle] }) else { continue }
            account.located(at: target)
            let picks = routes && signalling == .udp
            guard picks, account.derivesContact, let advertised = try? advertise(toward: target) else { continue }
            try? account.reach(at: advertised, remote: target)
        }
    }

    /// `sipral_account_looked_up`, for one answer; an account removed while
    /// the resolver ran is let go of quietly.
    private func lookedUp(account: SipralHandle, name: String, record: UInt32, _ answer: DnsLookupAnswer) {
        guard !isClosed else { return }
        try? retryingBusy {
            try Sipral.accountLookedUp(
                stack: handle, account: account, name: name, record: record, answer: answer.answer.rawValue,
                records: answer.records.joined(separator: ","), nowMs: nowMs()
            )
        }
    }

    /// `mediaHost`, else the route toward the media's source.
    func mediaHost(_ mediaHost: String?, account: Account?, destination: String?) -> String {
        if let mediaHost { return mediaHost }
        for peer in [destination, account?.registrarAddress] {
            if let peer, Self.isAddress(peer) {
                return Self.routeHost(toward: peer)
            }
        }
        return UDPSocket.parse(bindAddress).host
    }

    /// The account the stack added under `handle`, if it has not been removed.
    func account(_ handle: SipralHandle) -> Account? {
        movingQueue.sync { accounts[handle] }
    }

    /// Whether `.trace` logs whole SIP messages with their peers or
    /// pseudonymised (default); credentials and keys are removed either way
    /// (`sipral_stack_diagnostic_trace`).
    public func setDiagnosticTrace(_ on: Bool) throws {
        try retryingBusy { try Sipral.stackDiagnosticTrace(stack: handle, on: SipralStack.toggle(on)) }
    }

    /// What the stack runs with, every default filled in
    /// (`sipral_stack_settings`), with the SRTP suites its calls offer in
    /// order (`sipral_stack_srtp_suite_order`).
    public func settings() throws -> SipralSettings {
        let raw = try retryingBusy { try Sipral.stackSettings(stack: handle) }
        var suites = [UInt32](repeating: 0, count: Int(raw.srtp_suite_count))
        _ = try retryingBusy { try Sipral.stackSrtpSuiteOrder(stack: handle, outSuites: &suites) }
        return SipralSettings(raw, srtpSuites: suites.compactMap(SipralSrtpSuite.init(rawValue:)))
    }

    /// The kept calls' diagnostic record as JSON: each decision and why
    /// (`sipral_stack_diagnostics_json`).
    public func diagnosticsJson() throws -> String {
        var capacity = 4096
        while true {
            var buffer = [CChar](repeating: 0, count: capacity)
            do {
                let needed = try retryingBusy { try Sipral.stackDiagnosticsJson(stack: handle, buffer: &buffer) }
                let bytes = buffer.prefix(max(0, needed - 1)).map { UInt8(bitPattern: $0) }
                return String(decoding: bytes, as: UTF8.self)
            } catch let error as SipralError where error.status == .bufferTooSmall {
                capacity *= 4
            }
        }
    }

    func forgetAccount(_ account: SipralHandle) {
        movingQueue.sync { _ = accounts.removeValue(forKey: account) }
    }

    /// `sipral_call_place`, with this stack running the call's audio.
    ///
    /// The media socket opens before the INVITE; `Call.media` exists once
    /// `SipralEventKind.mediaStarted` arrives.
    ///
    /// Take `Call.events()` as soon as this returns: a fast answer is not
    /// replayed, though `Call.state`, `Call.media` and `Call.ended` still
    /// show it.
    ///
    /// With a `stunServer` this returns once the server answers or 5.5 s
    /// pass (and, with TURN, once the relay is allocated or refused);
    /// `takeIncomingCall` waits the same way. `ice` overrides the stack's
    /// policy. `headers` go on the INVITE as written (`Alert-Info`,
    /// `Answer-Mode`).
    ///
    /// `codecs` replaces the stack's order (`sipral_codec_info_t` names,
    /// comma-separated); linear audio is only offered as `L16/16000` or
    /// `L16/8000`. `text` offers real-time text on a second socket (RFC
    /// 4103), carried by `Media.sendText(_:)` and `Call.text()`; it is not
    /// offered with SRTP or ICE, which it would leave in the clear.
    /// `feedback` offers RTP/AVPF (RFC 4585, RFC 5506), which an RTP/AVP-only
    /// peer refuses; `focus` marks a conference focus (RFC 4579).
    /// `followRedirects` follows a 3xx (RFC 3261 §8.1.3.4); off, the 3xx
    /// ends the call and its `Contact` is the application's to act on.
    public func placeCall(
        account: Account,
        target: String,
        mediaHost: String? = nil,
        mediaPort: UInt16 = 0,
        destination: String? = nil,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil,
        headers: [SipralHeader] = [],
        codecs: String? = nil,
        text: Bool = false,
        feedback: Bool = false,
        focus: Bool = false,
        followRedirects: Bool = false
    ) throws -> Call {
        let mediaHost = self.mediaHost(mediaHost, account: account, destination: destination)
        let mediaSocket = try openMediaSocket(host: mediaHost, port: mediaPort)
        let textSocket: UDPSocket?
        do {
            textSocket = text ? try UDPSocket(host: mediaHost, port: 0) : nil
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }
        let stackHandle = handle

        let callHandle: SipralHandle
        do {
            try mapMediaSocket(mediaSocket)
            let now = nowMs()
            callHandle = try CStrings.with(
                [target, mediaSocket.localAddress, destination, codecs, textSocket?.localAddress]
            ) { parts in
                var config = sipral_call_config_t.sized()
                config.target = parts[0].pointer
                config.target_len = parts[0].count
                config.media_address = parts[1].pointer
                config.media_address_len = parts[1].count
                config.srtp = srtp?.rawValue ?? 0
                config.ice = ice?.rawValue ?? 0
                if let destinationPointer = parts[2].pointer {
                    config.destination = destinationPointer
                    config.destination_len = parts[2].count
                }
                config.codecs = parts[3].pointer
                config.codecs_len = parts[3].count
                config.text_address = parts[4].pointer
                config.text_address_len = parts[4].count
                config.feedback = feedback ? SipralToggle.on.rawValue : 0
                config.focus = focus ? 1 : 0
                config.follow_redirects = followRedirects ? 1 : 0
                return try retryingBusy {
                    try Sipral.callPlace(
                        stack: stackHandle, account: account.handle, config: config, configHeaders: headers, nowMs: now
                    )
                }
            }
        } catch {
            giveBackMediaSocket(mediaSocket)
            textSocket?.close()
            throw error
        }

        let call = Call(stack: self, handle: callHandle, mediaSocket: mediaSocket, textSocket: textSocket)
        registerCall(call)
        return call
    }

    /// Open a media socket for `event` (an `.incomingCall`) and answer.
    /// Early events can be missed; to see them all, use `takeIncomingCall`,
    /// take `Call.events()`, then `Call.answer()`.
    ///
    /// `text` accepts offered real-time text on its own socket; `codecs`,
    /// `focus` and `feedback` are as in `Call.answer(codecs:focus:feedback:)`.
    public func answerCall(
        _ event: SipralEvent,
        mediaHost: String? = nil,
        mediaPort: UInt16 = 0,
        text: Bool = false,
        codecs: String? = nil,
        focus: Bool = false,
        feedback: Bool = false
    ) throws -> Call {
        let call = try takeIncomingCall(event, mediaHost: mediaHost, mediaPort: mediaPort, text: text)
        try call.answer(codecs: codecs, focus: focus, feedback: feedback)
        return call
    }

    /// A `Call` for an incoming call that is left ringing: its media socket
    /// opened and its events routed, and nothing sent. `Call.answer()`
    /// answers it later, `Call.reject(code:)` refuses it.
    ///
    /// For a call shown to a person first: on iOS, bind it into
    /// `CallKitBridge` before the user taps Answer, so `CXAnswerCallAction`
    /// is its only answer. `answerCall` is this plus the answer.
    ///
    /// `text` binds a second socket at `mediaHost` for the real-time text
    /// the offer carries, which `Call.answer()` then takes.
    public func takeIncomingCall(
        _ event: SipralEvent,
        mediaHost: String? = nil,
        mediaPort: UInt16 = 0,
        text: Bool = false
    ) throws -> Call {
        let mediaHost = self.mediaHost(mediaHost, account: account(event.account), destination: nil)
        let mediaSocket = try openMediaSocket(host: mediaHost, port: mediaPort)
        let textSocket: UDPSocket?
        do {
            try mapMediaSocket(mediaSocket)
            textSocket = text ? try UDPSocket(host: mediaHost, port: 0) : nil
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }
        let call = Call(
            stack: self, handle: event.call, mediaSocket: mediaSocket, incoming: event.callData, textSocket: textSocket
        )
        registerCall(call)

        // A CANCEL can land between `incomingCall` and here; its `callEnded`
        // then reached no `Call`, and a `Call` minted on the dead handle
        // would never end (streams open, CallKit never told). So liveness is
        // checked now, and any failure drops the call.
        do {
            _ = try call.state
        } catch {
            call.close()
            throw error
        }
        return call
    }

    public func rejectCall(_ event: SipralEvent, code: UInt32 = 486) throws {
        try retryingBusy {
            try Sipral.callReject(stack: handle, call: event.call, code: code, nowMs: nowMs())
        }
    }

    /// Answer `event`'s incoming call with a 3xx without taking it (no media
    /// socket). 302 is call forwarding; `targets` are in order of
    /// preference; `reason` adds a `Diversion`.
    public func redirectCall(
        _ event: SipralEvent, to targets: [String], status: UInt32 = 302, reason: String? = nil
    ) throws {
        try redirect(call: event.call, to: targets, status: status, reason: reason)
    }

    func redirect(call: SipralHandle, to targets: [String], status: UInt32, reason: String?) throws {
        try retryingBusy {
            try Sipral.callRedirect(
                stack: handle, call: call, statusCode: status, targets: targets.joined(separator: ","),
                reason: reason ?? "", nowMs: nowMs()
            )
        }
    }

    /// Who is calling beyond the `From`, before deciding to answer. See
    /// `CallerIdentity`.
    public func callerIdentity(of event: SipralEvent) throws -> CallerIdentity {
        try IdentityReader.identity(stack: self, call: event.call, data: event.callData)
    }

    /// How the `.incomingCall` `event` names asked to be answered and rung.
    public func answering(of event: SipralEvent) throws -> Answering {
        try IdentityReader.answering(stack: self, call: event.call, data: event.callData)
    }

    /// Accept an out-of-dialog REFER (`event`, a `.referral` with a zero
    /// `referralData.statusCode`) and place the call it asks for
    /// (`sipral_call_accept_transfer`).
    ///
    /// The stack answers 202, reports progress to the referrer, and places
    /// the call from the event's account to the REFER's target. The returned
    /// `Call` is that call, with its own media socket. Whoever sent the
    /// REFER can make this line dial anything, so this is never automatic.
    public func acceptReferral(
        _ event: SipralEvent,
        mediaHost: String? = nil,
        mediaPort: UInt16 = 0,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil
    ) throws -> Call {
        let mediaHost = self.mediaHost(mediaHost, account: account(event.account), destination: nil)
        let mediaSocket = try openMediaSocket(host: mediaHost, port: mediaPort)
        let stackHandle = handle
        let placed: SipralHandle
        do {
            try mapMediaSocket(mediaSocket)
            let now = nowMs()
            placed = try CStrings.with([mediaSocket.localAddress]) { parts in
                var config = sipral_call_config_t.sized()
                config.media_address = parts[0].pointer
                config.media_address_len = parts[0].count
                config.srtp = srtp?.rawValue ?? 0
                config.ice = ice?.rawValue ?? 0
                return try retryingBusy {
                    try Sipral.callAcceptTransfer(
                        stack: stackHandle, call: event.call, config: config, configHeaders: [], nowMs: now
                    )
                }
            }
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }
        let call = Call(stack: self, handle: placed, mediaSocket: mediaSocket)
        registerCall(call)
        return call
    }

    /// Refuse an out-of-dialog REFER with `code`, 300 to 699.
    public func rejectReferral(_ event: SipralEvent, code: UInt32 = 603) throws {
        try retryingBusy {
            try Sipral.callRejectTransfer(stack: handle, call: event.call, code: code, nowMs: nowMs())
        }
    }

    func callFor(_ handle: SipralHandle) -> Call? {
        callsQueue.sync { calls[handle] }
    }

    func registerCall(_ call: Call) {
        callsQueue.sync { calls[call.handle] = call }
        if let transport = turn?.transport, Self.overStream(transport.rawValue) {
            natQueue.sync { turnSockets[call.handle] = call.mediaAddress }
        }
    }

    func forgetCall(_ handle: SipralHandle) {
        callsQueue.sync { _ = calls.removeValue(forKey: handle) }
    }

    // MARK: - media sockets behind a NAT

    /// STUN gives up after 5.5 s, an unanswered TURN Allocate after 39.5 s.
    private var natPatience: DispatchTimeInterval {
        turnServer == nil ? .seconds(7) : .seconds(42)
    }

    /// Map a media socket and wait for the servers' answers: placing or
    /// answering before that is `SIPRAL_STATUS_WRONG_STATE`. The poll thread
    /// reads the socket until the call's media handle exists. No-op without
    /// a STUN server.
    @discardableResult
    private func mapMediaSocket(_ socket: UDPSocket) throws -> String? {
        guard stunServer != nil else { return nil }
        let local = socket.localAddress
        let waiter = NatWaiter(needsRelay: turnServer != nil)
        natQueue.sync {
            stunSockets[local] = socket
            natWaiters[local] = waiter
        }
        defer { natQueue.sync { _ = natWaiters.removeValue(forKey: local) } }
        try retryingBusy { try Sipral.stackNatMap(stack: handle, local: local, nowMs: nowMs()) }
        _ = waiter.done.wait(timeout: .now() + natPatience)
        return natQueue.sync { waiter.publicAddress }
    }

    /// The public address of the socket `Call.moveMedia` binds, or `nil`
    /// without STUN.
    func mapMovedSocket(_ socket: UDPSocket) throws -> String? {
        try mapMediaSocket(socket)
    }

    /// Stop refreshing the old socket's mapping. No-op without STUN.
    func forgetMapping(_ local: String) {
        guard stunServer != nil else { return }
        try? retryingBusy { try Sipral.stackNatUnmap(stack: handle, local: local, nowMs: nowMs()) }
    }

    /// The poll thread's half of `mapMediaSocket`'s wait.
    private func noteNat(_ event: SipralEvent) {
        let local: String
        if let nat = event.natData, !nat.signalling {
            local = nat.local
        } else if let relay = event.relayData {
            local = relay.local
        } else {
            return
        }
        natQueue.sync {
            guard let waiter = natWaiters[local] else { return }
            if let nat = event.natData {
                waiter.mapped = true
                waiter.publicAddress = nat.mapped
            } else {
                waiter.relayed = true
            }
            if waiter.mapped && waiter.relayed { waiter.done.signal() }
        }
    }

    /// From now on `Media`'s own thread reads the socket. Called on the poll
    /// thread in the poll that raised `mediaStarted`.
    func mediaSocketTaken(_ local: String) {
        natQueue.sync { _ = stunSockets.removeValue(forKey: local) }
    }

    /// For a socket whose call never got media: unmap, send the relay-release
    /// Refresh from the socket itself, then close it.
    func giveBackMediaSocket(_ socket: UDPSocket) {
        let local = socket.localAddress
        if let port = local.split(separator: ":").last.flatMap({ UInt16($0) }) {
            giveBackPort(port)
        }
        let named = natQueue.sync { stunSockets[local] != nil }
        if named {
            try? retryingBusy { try Sipral.stackNatUnmap(stack: handle, local: local, nowMs: nowMs()) }
            drainStun()
        }
        natQueue.sync {
            _ = stunSockets.removeValue(forKey: local)
            socket.close()
        }
    }

    /// Send what the media sockets owe, each from the socket the stack names,
    /// since the source address is what the server observes. Own buffers:
    /// the poll thread and a thread releasing a socket can both be here.
    private func drainStun() {
        guard stunServer != nil else { return }
        var data = [UInt8](repeating: 0, count: 1500)
        var destination = [UInt8](repeating: 0, count: 128)
        var source = [UInt8](repeating: 0, count: 128)
        while true {
            let taken: (payload: [UInt8], destination: String, source: String, protocolRaw: UInt32)? =
                data.withUnsafeMutableBufferPointer { dataBuf in
                destination.withUnsafeMutableBufferPointer { destinationBuf in
                    source.withUnsafeMutableBufferPointer { sourceBuf in
                        var transmit = sipral_transmit_t.sized()
                        transmit.data = dataBuf.baseAddress
                        transmit.capacity = dataBuf.count
                        transmit.destination = UnsafeMutableRawPointer(destinationBuf.baseAddress!)
                            .assumingMemoryBound(to: CChar.self)
                        transmit.destination_capacity = destinationBuf.count
                        transmit.source = UnsafeMutableRawPointer(sourceBuf.baseAddress!)
                            .assumingMemoryBound(to: CChar.self)
                        transmit.source_capacity = sourceBuf.count
                        guard (try? retryingBusy({ try Sipral.stackPollStun(stack: handle, transmit: &transmit) })) != nil,
                              transmit.len > 0 else { return nil }
                        return (
                            Array(dataBuf.prefix(transmit.len)),
                            String(decoding: destinationBuf.prefix(transmit.destination_len), as: UTF8.self),
                            String(decoding: sourceBuf.prefix(transmit.source_len), as: UTF8.self),
                            transmit.protocol
                        )
                    }
                }
            }
            guard let taken else { return }
            if Self.overStream(taken.protocolRaw) {
                // On the TURN connection: a network blocking UDP would drop
                // a datagram.
                writeTurn(taken.source, taken.payload)
                continue
            }
            natQueue.sync { _ = stunSockets[taken.source]?.send(taken.payload, to: taken.destination) }
        }
    }

    // MARK: - a TURN server reached over TCP or TLS

    private static func overStream(_ protocolRaw: UInt32) -> Bool {
        protocolRaw == SipralTransport.tcp.rawValue || protocolRaw == SipralTransport.tls.rawValue
    }

    /// Write `payload` whole on `local`'s TURN connection. Thread-safe.
    func writeTurn(_ local: String, _ payload: [UInt8]) {
        let connection = natQueue.sync { turnConnections[local] }
        connection?.send(payload)
    }

    /// Act on `turnStream` after this round's queues were written.
    private func actOnTurnStreams() {
        let asked = natQueue.sync { () -> [TurnStreamEventData] in
            defer { turnAsked = [] }
            return turnAsked
        }
        for said in asked {
            switch said.state {
            case .open:
                openTurn(said)
            case .close:
                let connection = natQueue.sync { () -> TurnConnection? in
                    turnSockets = turnSockets.filter { $0.value != said.local }
                    return turnConnections.removeValue(forKey: said.local)
                }
                connection?.close()
            case nil:
                break
            }
        }
    }

    /// Connect `said.local` to the TURN server and feed the stack the result.
    private func openTurn(_ said: TurnStreamEventData) {
        guard let turn else { return }
        let local = said.local
        let connection = TurnConnection(
            local: local, server: said.server, turn: turn,
            ready: { [weak self] opened in
                guard let self else { return }
                if opened {
                    try? retryingBusy {
                        try Sipral.stackTurnConnected(stack: self.handle, local: local, nowMs: self.nowMs())
                    }
                } else {
                    self.natQueue.sync { _ = self.turnConnections.removeValue(forKey: local) }
                    try? retryingBusy {
                        try Sipral.stackTurnClosed(stack: self.handle, local: local, nowMs: self.nowMs())
                    }
                }
            },
            bytes: { [weak self] bytes in self?.turnReceived(local, bytes) },
            closed: { [weak self] in
                guard let self else { return }
                let held = self.natQueue.sync { self.turnConnections.removeValue(forKey: local) }
                guard held != nil else { return }
                try? retryingBusy {
                    try Sipral.stackTurnClosed(stack: self.handle, local: local, nowMs: self.nowMs())
                }
            }
        )
        natQueue.sync { turnConnections[local] = connection }
    }

    /// Every byte in order (a stream that loses one never resyncs), so a
    /// busy stack is waited for. A connection the stack found broken is
    /// closed silently.
    private func turnReceived(_ local: String, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackTurnReceive(stack: handle, local: local, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy || error.status == .clockBehind {
                usleep(1_000)
            } catch let error as SipralError where error.status == .streamBroken {
                let connection = natQueue.sync { turnConnections.removeValue(forKey: local) }
                connection?.close()
                return
            } catch {
                return
            }
        }
    }

    /// Collected under `natQueue`, delivered outside it.
    private func receiveStun() {
        let arrived: [(data: [UInt8], from: String, to: String)] = natQueue.sync {
            var arrived: [(data: [UInt8], from: String, to: String)] = []
            for (local, socket) in stunSockets {
                while let (data, from) = socket.receive(capacity: 2048) {
                    arrived.append((data, from, local))
                }
            }
            return arrived
        }
        for datagram in arrived {
            // A datagram from a stranger, or early media before the session
            // opens, is refused and costs that one datagram.
            try? retryingBusy {
                try Sipral.stackReceiveStun(
                    stack: handle, data: datagram.data, from: datagram.from, to: datagram.to, nowMs: nowMs()
                )
            }
        }
    }

    private var stunDescriptors: [Int32] {
        natQueue.sync { stunSockets.values.map(\.fd) }
    }

    // MARK: - the network changing under the stack

    /// The device's network, for `sipral_stack_network_changed`: link kind,
    /// IPv4 address without port, the interface name (opaque), and whether
    /// DNS works.
    public struct Network: Sendable, Equatable {
        public var link: SipralLink
        public var address: String?
        public var interface: String?
        public var resolves: Bool

        public init(link: SipralLink, address: String? = nil, interface: String? = nil, resolves: Bool = true) {
            self.link = link
            self.address = address
            self.interface = interface
            self.resolves = resolves
        }
    }

    /// The bind host, or the new network's after `networkChanged(to:)`.
    var currentHost: String {
        stateQueue.sync { network.address } ?? UDPSocket.parse(bindAddress).host
    }

    /// The platform reports a network change (`sipral_stack_network_changed`).
    ///
    /// On a new address or interface (`SipralRecovery.rebuild`) the UDP
    /// signalling socket is rebound at `to.address` on the same port (see
    /// `keptSignallingPort`) and every account is repointed, so the next
    /// REGISTER names the new address. With no `bindHost` the socket stays
    /// on every interface and the advertised address is re-picked as at
    /// creation. Each live call then raises `callAddressWanted`: the far end
    /// still sends to the old address until `Call.moveMedia()`. A roam that
    /// keeps the address only re-registers. Safe to call on every platform
    /// notification; most answers are `.nothing`.
    @discardableResult
    public func networkChanged(to next: Network) throws -> SipralRecovery {
        try movingQueue.sync {
            let previous = stateQueue.sync { network }
            let picksRoutes = routes && signalling == .udp
            let moves = next.link != .down && (next.address != previous.address || next.interface != previous.interface)
            var rebound: String?
            if moves, signalling != .udp {
                let host = next.address ?? UDPSocket.parse(bindAddress).host
                signallingQueue.sync { linkHost = host }
                let old = signallingQueue.sync { () -> SignallingConnection? in
                    defer { link = nil }
                    return link
                }
                old?.close()
                do {
                    let made = try SignallingConnection(
                        server: signallingServer!, bindHost: host, transport: signalling,
                        serverName: tlsServerName, trust: tlsTrust, patienceMs: Self.patienceMs
                    )
                    try install(made)
                    rebound = made.local
                } catch let refusal as SignallingRefusal {
                    report(refusal)
                    reconnectLater()
                }
            } else if moves, picksRoutes {
                // A wildcard socket already receives at the new address;
                // only the advertised one moves. An address this machine
                // lacks is refused, as for a bound stack.
                if let address = next.address {
                    let probe = try UDPSocket(host: address, port: 0)
                    probe.close()
                }
                signallingQueue.sync { _keptSignallingPort = true }
                rebound = try advertiseAgain(after: next.address)
            } else if moves {
                let host = next.address ?? UDPSocket.parse(bindAddress).host
                let fresh = try signallingSocket(at: host)
                do {
                    // Called directly: only a null pointer says "no remote",
                    // and the generated wrapper passes "" as a real string.
                    let local = fresh.localAddress
                    try retryingBusy {
                        var bound: UInt32 = 0
                        let status = local.withCString {
                            sipral_stack_transport_bind(
                                handle, Sipral.transportMain, 0, $0, local.utf8.count, nil, 0, nowMs(), &bound
                            )
                        }
                        try Sipral.check(status)
                    }
                } catch {
                    fresh.close()
                    throw error
                }
                let old = signallingQueue.sync { () -> UDPSocket? in
                    let old = socket
                    socket = fresh
                    return old
                }
                signallingQueue.sync { old?.close() }
                rebound = fresh.localAddress
            }
            let raw = try retryingBusy {
                try Sipral.stackNetworkChanged(
                    stack: handle,
                    fromLink: previous.link.rawValue, fromAddress: previous.address ?? "",
                    fromInterface: previous.interface ?? "", fromResolves: previous.resolves ? 1 : 0,
                    toLink: next.link.rawValue, toAddress: next.address ?? "",
                    toInterface: next.interface ?? "", toResolves: next.resolves ? 1 : 0,
                    nowMs: nowMs()
                )
            }
            stateQueue.sync {
                network = Network(
                    link: next.link, address: next.address ?? previous.address,
                    interface: next.interface, resolves: next.resolves
                )
            }
            let recovery = SipralRecovery(rawValue: raw) ?? .unknown
            if let rebound {
                for account in accounts.values {
                    // Each account: the route toward its own server.
                    let server = account.registrarAddress
                    var local = rebound
                    if picksRoutes, account.derivesContact, Self.isAddress(server) {
                        local = try advertise(toward: server)
                    }
                    try account.rebind(local: local, previous: previous.address)
                }
            }
            return recovery
        }
    }

    /// Rebind at `host` on the same port, or a system-chosen one if it is
    /// taken (`keptSignallingPort`). The old socket may hold the port itself,
    /// so it is released before a second try.
    private func signallingSocket(at host: String) throws -> UDPSocket {
        let inUse = signallingQueue.sync { socket.map { UDPSocket.parse($0.localAddress).port } } ?? 0
        let wanted = chosenPort != 0 ? chosenPort : inUse
        var made = wanted == 0 ? nil : try? UDPSocket(host: host, port: wanted)
        // Released only for an address this machine has; otherwise the
        // throw below leaves the current socket open.
        if made == nil, wanted != 0, inUse == wanted, let usable = try? UDPSocket(host: host, port: 0) {
            usable.close()
            signallingQueue.sync {
                socket?.close()
                socket = nil
            }
            made = try? UDPSocket(host: host, port: wanted)
        }
        let kept = made != nil || wanted == 0
        let bound = try made ?? UDPSocket(host: host, port: 0)
        signallingQueue.sync { _keptSignallingPort = kept }
        return bound
    }

    /// Runs `body` with no network change in progress (for `Call.moveMedia`).
    func moving<T>(_ body: () throws -> T) throws -> T {
        try movingQueue.sync(execute: body)
    }

    // MARK: - the library's own audio engine

    /// Sends an encoded microphone packet. Runs on the engine's thread,
    /// which must not call back into the engine.
    fileprivate func transmitAudio(call: SipralHandle, payload: [UInt8], destination: String, protocolRaw: UInt32) {
        guard let target = callFor(call) else { return }
        if Self.overStream(protocolRaw) {
            writeTurn(target.mediaAddress, payload)
        } else {
            target.sendOnMediaSocket(payload, to: destination)
        }
    }

    // MARK: - the poll thread

    /// Every event goes to its call, if it has one, and to `events`.
    ///
    /// `resolveNeeded` is passed on, not answered: the dialog keeps the
    /// flow its INVITE used (the only path through a NAT). Answering with the
    /// far `Contact` as a literal would move the call there, and behind a NAT
    /// the BYE would go nowhere. An application with a real lookup answers
    /// via `Sipral.stackResolved`.
    fileprivate func handleEvent(_ raw: sipral_event_t) {
        let event = SipralEventDecoder.decode(raw)
        if let stream = event.turnStreamData {
            natQueue.sync { turnAsked.append(stream) }
        }
        if signalling == .udp, let wanted = event.transportWantedData {
            signallingQueue.sync { streamsAsked.append(wanted) }
        }
        if let locate = event.locateData {
            if event.kindRaw == SipralEventKind.lookupWanted.rawValue, let name = locate.name {
                signallingQueue.sync { lookupsAsked.append((event.account, name, locate.recordRaw)) }
            } else if event.kindRaw == SipralEventKind.located.rawValue,
                      let first = locate.targets?.split(separator: ",").first {
                signallingQueue.sync { locatedAsked.append((event.account, String(first))) }
            }
        }
        if let lost = event.transportFailedData {
            if signalling == .udp {
                noteStreamLetGo(lost.transport)
            } else if lost.transport == Sipral.transportMain {
                signallingQueue.sync { mainLetGo = true }
            }
        }
        noteNat(event)
        if let call = callFor(event.call) {
            call.deliver(event)
        }
        if event.kindRaw == SipralEventKind.callEnded.rawValue {
            recordingEnded(event.call)
        }
        eventBroadcast.send(event)
    }

    private func drainTransmit() {
        while true {
            var transmit = sipral_transmit_t.sized()
            transmit.data = transmitData
            transmit.capacity = 65536
            transmit.destination = transmitDestination
            transmit.destination_capacity = 128
            transmit.source = nil
            transmit.source_capacity = 0
            guard (try? Sipral.stackPollTransmit(stack: handle, transmit: &transmit)) != nil else { return }
            guard transmit.len > 0 else { return }
            let payload = Array(UnsafeBufferPointer(start: transmitData, count: transmit.len))
            if transmit.transport != Sipral.transportMain {
                // A recording or oversize-request connection.
                signallingQueue.sync {
                    recordingLinks[transmit.transport] ?? streamLinks[transmit.transport]?.link
                }?.send(payload)
                continue
            }
            if signalling != .udp {
                // One connection carries everything: the server is the
                // outbound proxy.
                signallingQueue.sync { link }?.send(payload)
                continue
            }
            let destination = transmitDestination.withMemoryRebound(to: UInt8.self, capacity: transmit.destination_len) {
                String(decoding: UnsafeBufferPointer(start: $0, count: transmit.destination_len), as: UTF8.self)
            }
            signallingQueue.sync { _ = socket?.send(payload, to: destination) }
        }
    }

    /// Send what an ended call still owes (RTCP BYE, TURN release) from its
    /// media socket to the address the stack names: under ICE the chosen
    /// path, not necessarily where media last came from.
    private func drainFarewells() {
        var destination = [UInt8](repeating: 0, count: 128)
        while true {
            let taken: (call: SipralHandle, payload: [UInt8], destination: String, protocolRaw: UInt32)? =
                destination.withUnsafeMutableBufferPointer { destinationBuf in
                    var packet = sipral_media_packet_t.sized()
                    packet.data = farewellData
                    packet.capacity = 1500
                    packet.destination = UnsafeMutableRawPointer(destinationBuf.baseAddress!)
                        .assumingMemoryBound(to: CChar.self)
                    packet.destination_capacity = destinationBuf.count
                    guard let call = try? Sipral.stackPollFarewell(stack: handle, packet: &packet),
                          packet.len > 0 else { return nil }
                    return (
                        call,
                        Array(UnsafeBufferPointer(start: farewellData, count: packet.len)),
                        String(decoding: destinationBuf.prefix(packet.destination_len), as: UTF8.self),
                        packet.protocol
                    )
                }
            guard let taken else { return }
            if Self.overStream(taken.protocolRaw) {
                // The relay's connection outlives the call.
                if let local = natQueue.sync(execute: { turnSockets[taken.call] }) {
                    writeTurn(local, taken.payload)
                }
                continue
            }
            guard let target = callFor(taken.call) else { continue }
            let address = taken.destination.isEmpty ? target.media?.remoteAddress : taken.destination
            guard let address else { continue }
            target.sendOnMediaSocket(taken.payload, to: address)
        }
    }

    private func run() {
        while !isClosed {
            // Signalling socket first (absent over TCP/TLS: -1 is ignored by
            // poll), then media sockets awaiting their call's media handle.
            let signalling = signallingQueue.sync { socket }
            var pfds = [pollfd(fd: signalling?.fd ?? -1, events: Int16(POLLIN), revents: 0)]
            pfds += stunDescriptors.map { pollfd(fd: $0, events: Int16(POLLIN), revents: 0) }
            _ = pfds.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 50) }
            if pfds.dropFirst().contains(where: { $0.revents & Int16(POLLIN) != 0 }) {
                receiveStun()
            }
            if let signalling, pfds[0].revents & Int16(POLLIN) != 0 {
                let local = bindAddress
                while let (data, from) = signallingQueue.sync(execute: {
                    socket === signalling ? signalling.receive() : nil
                }) {
                    // `to` is passed explicitly: the generated wrapper turns
                    // "" into a non-null pointer, which the C side refuses
                    // instead of reading as "my own bind address". Garbage
                    // datagrams are refused and do not stop the loop.
                    try? Sipral.stackReceiveDatagram(
                        stack: handle, transport: Sipral.transportMain, data: data, from: from,
                        to: local, nowMs: nowMs()
                    )
                }
            }
            guard (try? Sipral.stackPoll(stack: handle, nowMs: nowMs())) != nil else { continue }
            drainTransmit()
            drainStun()
            drainFarewells()
            actOnTurnStreams()
            actOnStreamsWanted()
            actOnMainLetGo()
            actOnLookups()
        }
        closedSemaphore.signal()
    }

    private var isClosed: Bool { stateQueue.sync { closed } }

    /// `sipral_stack_destroy`, and everything this wrapper opened.
    ///
    /// Open calls are hung up first, while the poll thread and media sockets
    /// can still send the BYEs and farewells; `Call.close()` runs only after
    /// a poll round has drained them.
    public func close() {
        let wasClosed = stateQueue.sync { () -> Bool in
            defer { closed = true }
            return closed
        }
        guard !wasClosed else { return }

        let openCalls = callsQueue.sync { Array(calls.values) }
        for call in openCalls where !call.ended {
            try? call.hangup()
        }
        if !openCalls.isEmpty {
            usleep(200_000)
        }
        for call in openCalls {
            call.close()
        }
        // A socket mapped for a call that was never placed still holds a
        // relay the server would keep for up to ten minutes after the stack
        // is gone, since `sipral_stack_destroy` sends nothing.
        let unspent = natQueue.sync { Array(stunSockets.values) }
        for socket in unspent {
            giveBackMediaSocket(socket)
        }

        _ = closedSemaphore.wait(timeout: .now() + 5)
        // Remaining TURN connections: releases were sent above.
        let connections = natQueue.sync { () -> [TurnConnection] in
            defer { turnConnections = [:] }
            return Array(turnConnections.values)
        }
        for connection in connections {
            connection.close()
        }
        let open = signallingQueue.sync { () -> SignallingConnection? in
            defer { link = nil }
            return link
        }
        open?.close()
        let toRecorders = signallingQueue.sync { () -> [SignallingConnection] in
            defer { recordingLinks = [:] }
            return Array(recordingLinks.values)
        }
        toRecorders.forEach { $0.close() }
        let streams = signallingQueue.sync { () -> [SignallingConnection] in
            defer { streamLinks = [:] }
            return streamLinks.values.map(\.link)
        }
        streams.forEach { $0.close() }
        try? Sipral.stackDestroy(stack: handle)
        eventBroadcast.finish()
        signallingQueue.sync { socket?.close() }
    }
}

/// Retries `SIPRAL_STATUS_BUSY`: the C ABI refuses a second thread rather
/// than blocking it, and the poll thread colliding with a caller is
/// ordinary. `SIPRAL_STATUS_CLOCK_BEHIND` is retried too: `body` reads
/// `nowMs()` just before the call, so being behind only means the poll
/// thread got in between, and the next reading is later.
func retryingBusy<T>(_ body: () throws -> T) throws -> T {
    let deadline = DispatchTime.now() + 0.5
    while true {
        do {
            return try body()
        } catch let error as SipralError where error.status == .busy || error.status == .clockBehind {
            if DispatchTime.now() >= deadline { throw error }
            usleep(1_000)
        }
    }
}

/// The C callback: runs on the poll thread, with nothing held
/// (`docs/08-ffi.md`, "Nothing is held while the callback runs").
private func sipralStackEventTrampoline(
    _ event: UnsafePointer<sipral_event_t>?, _ userData: UnsafeMutableRawPointer?
) {
    guard let event, let userData else { return }
    let box = Unmanaged<SipralStack.StackBox>.fromOpaque(userData).takeUnretainedValue()
    box.stack?.handleEvent(event.pointee)
}

/// Runs on whichever thread just left the stack, with no lock held.
private func sipralLogTrampoline(
    _ record: UnsafePointer<sipral_log_record_t>?, _ userData: UnsafeMutableRawPointer?
) {
    guard let record, let userData else { return }
    let line = record.pointee
    guard line.size >= MemoryLayout<sipral_log_record_t>.size else { return }
    let text = { (pointer: UnsafePointer<CChar>?, count: Int) -> String in
        guard let pointer else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: pointer, count: count), as: UTF8.self)
    }
    let box = Unmanaged<SipralStack.StackBox>.fromOpaque(userData).takeUnretainedValue()
    let handler = box.logQueue.sync { box.logHandler }
    handler?(
        SipralLogLevel(rawValue: line.level) ?? .debug,
        text(line.target, line.target_len),
        text(line.message, line.message_len),
        line.suppressed
    )
}

/// Runs on the engine thread; the packet is valid only until return, so it
/// is copied, and nothing here calls back into the engine.
private func sipralAudioTransmitTrampoline(
    _ transmit: UnsafePointer<sipral_audio_transmit_t>?, _ userData: UnsafeMutableRawPointer?
) {
    guard let transmit, let userData else { return }
    let packet = transmit.pointee
    guard packet.size >= MemoryLayout<sipral_audio_transmit_t>.size,
          let payload = packet.payload, packet.payload_len > 0 else { return }
    let bytes = Array(UnsafeBufferPointer(start: payload, count: packet.payload_len))
    let destination = packet.destination.map {
        String(decoding: UnsafeRawBufferPointer(start: $0, count: packet.destination_len), as: UTF8.self)
    } ?? ""
    let box = Unmanaged<SipralStack.StackBox>.fromOpaque(userData).takeUnretainedValue()
    box.stack?.transmitAudio(call: packet.call, payload: bytes, destination: destination, protocolRaw: packet.protocol)
}
