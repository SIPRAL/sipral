// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CSipral
import Dispatch

/// One `sipral_stack_create` handle, its socket and its poll thread.
///
/// This is the object an application reaches for. It owns the UDP socket
/// signalling travels on, a background thread that drains `sipral_stack_poll`
/// and the transport queues around it, and the `AsyncStream`s events land on
/// -- the layer `SipralAbi.swift` (printed by `tools/abi-gen` from
/// `crates/sipral-ffi`) is written against directly, the way
/// `bindings/python/sipral/stack.py`'s `Stack` is the same shape in Python
/// (`docs/08-ffi.md`, "Swift").
///
/// **Threading.** The C callback (`docs/08-ffi.md`, "Events arrive on one
/// callback") lands on this stack's own poll thread and is decoded there,
/// synchronously, into a `Sendable` `SipralEvent` before it ever reaches
/// `events()`: nothing past that point touches the pointers `sipral_event_t`
/// only promises for the length of the callback. Every reader `events()`
/// hands out is a Swift `AsyncStream` of its own, and
/// `Continuation.yield` is documented safe to call from any thread, which
/// is what lets the poll thread feed each of them directly with no further
/// hop, one after another, in the order the events were raised. Every
/// other member here that calls into the C ABI may be called from any
/// thread the application likes; a collision with the poll
/// thread already inside the stack's lock is `SIPRAL_STATUS_BUSY` and is
/// retried for up to half a second before it is thrown (`docs/08-ffi.md`,
/// "Signalling on one stack is one thread at a time").
public final class SipralStack: @unchecked Sendable {
    public let handle: SipralHandle

    /// The signalling socket's address, `host:port`: where it was bound, and
    /// after `networkChanged(to:)` where it is bound now. Over TCP or TLS,
    /// the address the connection to the server was made from, which moves
    /// with every connection made again.
    public var bindAddress: String {
        signallingQueue.sync { socket?.localAddress ?? linkLocal }
    }

    /// What SIP travels over: UDP, or one TCP or TLS connection to the
    /// server.
    public let signalling: SipralTransport

    /// Whether SIP can go out now: always over UDP, and over TCP or TLS
    /// while the connection to the server stands.
    public var connected: Bool {
        signalling == .udp || signallingQueue.sync { link != nil }
    }

    /// Who runs this stack's audio, as it was created.
    public let audioMode: AudioMode

    /// The library's audio engine -- the devices, their gain, mute and
    /// level, the ring and when they are open -- in `AudioMode.device`, and
    /// `nil` in `.application`, where the application runs the audio itself.
    public private(set) var audio: AudioDevices?

    private let eventBroadcast = Broadcast<SipralEvent>(
        label: "org.sipral.stack.events", policy: .bufferingNewest(Call.eventBuffer)
    )

    /// A new reader of every event this stack raises, decoded whole. A
    /// consumer that wants only one call's events reads `Call.events()`
    /// instead.
    ///
    /// Every call returns a stream of its own, and every stream gets every
    /// event from the moment it is taken, in the order the stack raised
    /// them -- an application's main loop and a second one waiting for the
    /// `SipralEventKind.incomingCall` a push announced can both read them.
    /// Nothing raised before a stream is taken reaches it, so take it
    /// before the action whose outcome it is meant to see: before
    /// `Account.register()` for the registration, before the call is placed
    /// for the far end's `incomingCall`. Each reader buffers on its own, up
    /// to `Call.eventBuffer` events, and drops its own oldest past that.
    /// Every stream finishes when `close()` runs, and one taken after that is
    /// finished from the start.
    public func events() -> AsyncStream<SipralEvent> {
        eventBroadcast.stream()
    }

    /// The signalling socket, guarded by `signallingQueue`: the poll thread
    /// reads and writes it, and `networkChanged(to:)` puts another in its
    /// place.
    private var socket: UDPSocket?
    private let signallingQueue = DispatchQueue(label: "org.sipral.stack.signalling")
    /// The connection SIP travels on over TCP or TLS, and the address it was
    /// made from, guarded by `signallingQueue`; `nil` while it is down.
    private var link: SignallingConnection?
    private var linkLocal = ""
    /// Where the connection goes, what name its certificate must carry, what
    /// it trusts, and the address it is made from.
    private let signallingServer: String?
    private let tlsServerName: String
    private let tlsTrust: TLSTrust
    private var linkHost: String
    private var reconnecting = false
    private let origin: DispatchTime

    /// Every account this stack added and has not removed, for
    /// `networkChanged(to:)` to point at the new address.
    private var accounts: [SipralHandle: Account] = [:]

    /// Serialises a network change with the calls it moves: the accounts are
    /// pointed at the new address before any call is offered there, so each
    /// re-INVITE carries the new `Contact`. Also guards `accounts`.
    private let movingQueue = DispatchQueue(label: "org.sipral.stack.moving")
    /// The network the stack was last told it is on, guarded by `stateQueue`.
    private var network: Network

    private let callsQueue = DispatchQueue(label: "org.sipral.stack.calls")
    private var calls: [SipralHandle: Call] = [:]
    private let box: StackBox
    private let closedSemaphore = DispatchSemaphore(value: 0)
    private let stateQueue = DispatchQueue(label: "org.sipral.stack.state")
    private var closed = false

    // Persistent scratch buffers for the poll loop -- allocated once, freed
    // in `close()`, the same way `bindings/python/sipral/stack.py` keeps its
    // `cffi` buffers on `self` rather than remaking them every pass.
    private let transmitData: UnsafeMutablePointer<UInt8>
    private let transmitDestination: UnsafeMutablePointer<CChar>
    private let farewellData: UnsafeMutablePointer<UInt8>

    /// Carries a weak back-reference to the `SipralStack` the C callback's
    /// `event_user_data` names. Allocated before `sipral_stack_create` is
    /// called, and filled in once `self` fully exists; no event can arrive
    /// before the poll thread starts, which happens strictly after that
    /// assignment.
    final class StackBox {
        weak var stack: SipralStack?
        /// Where `setLog` sends lines, read by the log trampoline on
        /// whichever thread has just let the stack go. Guarded by `logQueue`.
        var logHandler: LogHandler?
        let logQueue = DispatchQueue(label: "org.sipral.stack.log")
    }

    /// What `setLog` hands each line to: its level, which part of the stack
    /// wrote it, the line -- already redacted -- and how many lines a flood
    /// had turned away before it.
    public typealias LogHandler = @Sendable (SipralLogLevel, String, String, UInt64) -> Void

    /// The STUN server this stack asks where its sockets appear from, as
    /// `host:port`, or `nil` for a stack that asks nobody: the one it was
    /// created with, then the first of what `setStunServers(_:)` last named.
    public var stunServer: String? { natQueue.sync { currentStunServer } }
    /// What `stunServer` answers. Guarded by `natQueue`.
    private var currentStunServer: String?
    private let turnServer: String?
    private let turn: TurnServer?

    /// Every media socket's open connection to a TURN server reached over
    /// TCP or TLS, by the socket's `host:port`. Guarded by `natQueue`.
    private var turnConnections: [String: TurnConnection] = [:]
    /// Every call's media socket, by the call, for as long as the socket's
    /// connection to the TURN server stands: a call's last farewell -- the
    /// Refresh that gives its relay back -- can come after the `Call` itself
    /// was closed and forgotten, and still goes on that connection. Guarded
    /// by `natQueue`, and let go with the connection.
    private var turnSockets: [SipralHandle: String] = [:]
    /// What `SipralEventKind.turnStream` asked for during the poll that
    /// raised it -- nothing may call back into the stack from inside its own
    /// callback -- acted on right after that poll, on the poll thread.
    private var turnAsked: [TurnStreamEventData] = []

    /// Media sockets `sipral_stack_nat_map` named whose call has no media
    /// handle yet, by `host:port`: the poll thread reads them and hands what
    /// arrives to `sipral_stack_receive_stun`, and sends what
    /// `sipral_stack_poll_stun` names each of them as the source of. Guarded
    /// by `natQueue`, which also covers each socket's close, so the poll
    /// thread never writes to one that was just given back.
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
    /// Every option left `nil` is this build's own default, which is what a
    /// stack created before the option existed does. `ice` is what every
    /// call does about ICE (RFC 8445) unless `placeCall(ice:)` says
    /// otherwise; `SipralIce.off` by default.
    ///
    /// `stunServer`, as `host:port` -- an address, not a name -- turns on
    /// `SIPRAL_NAT_STUN`: the signalling socket asks it where it appears
    /// from, every account's `Contact` moves to that public address
    /// (`SipralEventKind.natMapping`, `NatEventData.signalling`), and every
    /// media socket `placeCall` or `takeIncomingCall` opens is asked the
    /// same before its call is described, so the SDP a far end reads names
    /// the address it can actually send to. `turn` adds a relay on a TURN
    /// server for each of those media sockets, offered as the call's relayed
    /// ICE candidate; it needs `stunServer` too, and a call only uses the
    /// relay under ICE. `TurnServer.transport` reaches it over TCP or TLS
    /// instead of UDP, the stack opening each connection itself.
    /// `g729AnnexB` allows G.729's silence compression
    /// (on by default). `SipralIce.lite` is for a server reachable at the
    /// address it advertises, answering full ICE peers, and nothing else
    /// (`docs/06-nat.md`, "ICE-lite").
    ///
    /// `referrals: true` hands a REFER outside any dialog -- click-to-dial
    /// from a switchboard -- to the application as `SipralEventKind.referral`,
    /// to take with `acceptReferral` or refuse with `rejectReferral`. Off by
    /// default, when every one is refused 403: a peer that can make a phone
    /// dial is a toll-fraud vector, so each one is the application's
    /// decision.
    ///
    /// `registrarKeepalive` keeps the registrar's flow open behind a NAT:
    /// every account `stunServer` showed to be behind one sends its
    /// registrar a double CRLF every `registrarKeepaliveMs` (zero for 25
    /// seconds, 1 000 to 120 000), so that a NAT filtering by address and
    /// port still lets the registrar's INVITE in minutes after the REGISTER.
    /// On by default; `false` turns it off, and an interval with it off is
    /// refused. Nothing is sent while the stack is suspended.
    ///
    /// `audio` says who runs the calls' audio: `AudioMode.platformDefault`,
    /// the library's own engine wherever this build has one for the platform,
    /// unless the application pumps the frames itself with `.application`.
    /// With `.device(activation: .manual)` the devices open only between
    /// `AudioDevices.activate()` and `deactivate()` -- CallKit's
    /// `didActivate` and `didDeactivate` -- rather than with the first call's
    /// media and the last call's end. `audioProbeMs` bounds how long a
    /// platform call about the devices may block before it is reported as
    /// `.deviceTimedOut` (zero for three seconds), and `audioDeviceRateHz` is
    /// the rate the devices are asked to run at (zero for 48 000); every call
    /// is resampled between its own rate and theirs.
    ///
    /// `maxDialogs` is the most calls the stack holds at once, either way
    /// (zero for 128): one that arrives past it is answered 503, and one
    /// placed past it throws `.limitReached`. `maxServerTransactions` is the
    /// most requests from other ends it works on at once (zero for 256).
    /// `diagnosticDecisions` and `diagnosticRecords` bound the diagnostic
    /// record: decisions kept per call (zero for 64) and calls kept (zero
    /// for 32).
    ///
    /// `network` is the network the stack starts on, what the first
    /// `networkChanged(to:)` compares with: a wired link at `bindHost`, on no
    /// interface in particular, unless the application knows better.
    ///
    /// `stunFallbacks` are the STUN servers to turn to, in order, when
    /// `stunServer` does not answer in five and a half seconds or answers
    /// without an address, each `host:port`: every socket asking the one that
    /// failed moves to the next at once, the one that failed is passed over
    /// for thirty seconds and twice as long each time it fails again, up to
    /// ten minutes, and `SipralEventKind.stunServer` says when the server in
    /// use moves or every one has failed.
    ///
    /// `rtpPortMin` and `rtpPortMax` are the range a firewall in front of
    /// this machine was opened for: every media socket this class opens
    /// without an explicit port then binds an even port from it, reserved
    /// with `sipral_stack_rtp_port_reserve`, with the odd one above kept for
    /// RTCP (RFC 3550 §11), and a call is refused a port outside it. Both
    /// zero -- the default -- leave the ports to the operating system. Every
    /// pair taken throws `.exhausted` rather than binding outside the range.
    ///
    /// `dtmfDetection` is when a call listens for keypad digits in the far
    /// end's audio: `.auto` on the calls that negotiated no telephone event,
    /// `.always` or `.off`; `Call.setDtmfDetection` changes it for one call.
    ///
    /// `signalling` is what SIP travels over: `.udp` (the default) on a
    /// socket bound at `bindHost`, or `.tcp` or `.tls` on one connection to
    /// `signallingServer` (`host:port` -- the registrar or the outbound
    /// proxy, 5061 for TLS by convention), which every account and every
    /// call on this stack then shares, and on which the server's own requests
    /// arrive. Over TLS -- on Apple platforms, where Network.framework is;
    /// elsewhere it throws `.notSupported` -- the server's certificate is
    /// checked against `tlsServerName` (the host part of `signallingServer`
    /// when `nil`) with `tlsTrust`: the system's authorities, a private
    /// authority beside them, or only one authority (`docs/22-tls.md`).
    /// Nothing here turns the check off.
    ///
    /// The first connection is made here, before this returns. When it
    /// fails, or later breaks, the stack is told why and raises
    /// `SipralEventKind.transportFailed`, whose `transportFailedData` says
    /// untrusted, a name that does not match, expired, a handshake refused
    /// or a server that refused the connection, with Security's own words;
    /// and this stack connects again, one second after the loss and twice as
    /// long after each attempt that fails, up to thirty seconds. Once
    /// connected again every account is pointed at the new connection and
    /// registered again if it was registering. `Account.register()` asked
    /// while it is down is kept for then; a call placed meanwhile throws
    /// `.transportDown`.
    ///
    /// `inviteLimit` is how fast one address may ring this stack:
    /// `InviteLimit.standard` (what every stack starts with, ten INVITEs at
    /// once then one every two seconds, past which a call is answered 480)
    /// or `.voiceAgent` for a service taking a trunk's calls.
    public init(
        audio: AudioMode = .platformDefault,
        bindHost: String = "127.0.0.1",
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
        inviteLimit: InviteLimit? = nil
    ) throws {
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
        self.tlsServerName = tlsServerName ?? signallingServer.map { UDPSocket.parse($0).host } ?? bindHost
        self.tlsTrust = tlsTrust
        self.linkHost = bindHost
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
                bound = "\(bindHost):\(bindPort)"
            }
        } else {
            let made = try UDPSocket(host: bindHost, port: bindPort)
            socket = made
            bound = made.localAddress
        }
        self.socket = socket
        self.linkLocal = bound
        self.audioMode = audio
        self.network = network ?? Network(link: .wired, address: bindHost)
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
                    return try Sipral.stackCreate(config: config)
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

    /// How long one attempt at the signalling connection may take, the TLS
    /// handshake included.
    private static let patienceMs = 5000

    /// What goes after the address in a `Contact` this layer writes:
    /// `;transport=tcp` or `;transport=tls` for a stack signalling over a
    /// connection (RFC 3261 §19.1.1), nothing over UDP.
    var contactParameters: String {
        switch signalling {
        case .tls: return ";transport=tls"
        case .tcp: return ";transport=tcp"
        default: return ""
        }
    }

    /// Tell the stack a connection is open, naming both ends, and start
    /// reading it.
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

    /// `sipral_stack_transport_failure`, never throwing on the way out.
    private func report(_ refusal: SignallingRefusal) {
        let detail = refusal.detail
        detail.withCString { text in
            var failure = sipral_transport_failure_t.sized()
            failure.transport = Sipral.transportMain
            failure.error = refusal.error.rawValue
            failure.tls = signalling == .tls ? refusal.tls.rawValue : SipralTlsFailure.none.rawValue
            failure.detail = detail.isEmpty ? nil : text
            failure.detail_len = detail.utf8.count
            _ = try? retryingBusy { try Sipral.stackTransportFailure(stack: handle, failure: failure, nowMs: nowMs()) }
        }
    }

    /// What the connection carried, to `sipral_stack_receive_stream`, every
    /// byte in order: a busy stack is waited for rather than skipped.
    private func linkReceived(_ made: SignallingConnection, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackReceiveStream(stack: handle, transport: Sipral.transportMain, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy {
                usleep(1000)
            } catch {
                // the framing is lost: the stack retired the transport and
                // said so itself
                lose(made, nil, tell: false)
                return
            }
        }
    }

    /// Close `made` if it is still the connection, tell the stack how it
    /// ended -- `sipral_stack_stream_closed` for an orderly close (`refusal`
    /// nil), `sipral_stack_transport_failure` otherwise, nothing when not
    /// `tell` -- and connect again.
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

    /// Every account moves to the new connection's address -- one added with
    /// a `Contact` of its own keeps it -- and every one that was registering
    /// registers again now rather than at its next back-off.
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

    /// A UDP socket for a call's media at `host`: at `port` when one is
    /// named, otherwise -- on a stack with an RTP range -- at an even port
    /// reserved from it (`sipral_stack_rtp_port_reserve`), where one another
    /// process already holds is given back and the next tried, and elsewhere
    /// wherever the operating system puts it. `.exhausted` once every pair
    /// is taken.
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

    /// `sipral_stack_rtp_port_release` for a port no call took, on a stack
    /// with a range. Best effort: a port a call did take comes back by
    /// itself when the call ends.
    func giveBackPort(_ port: UInt16) {
        guard rtpPorts != nil else { return }
        try? retryingBusy { try Sipral.stackRtpPortRelease(stack: handle, port: UInt32(port)) }
    }

    /// Send this stack's log to `handler` at `level` and louder, or turn it
    /// off with `.off` or a `nil` handler (`sipral_stack_log`). The handler
    /// runs on whichever thread has just finished a call into the stack --
    /// the poll thread, usually -- with the stack let go, so it may call back
    /// into it. Every line is already redacted: no user part, number, IP
    /// address or credential reaches it.
    public func setLog(level: SipralLogLevel, handler: LogHandler?) throws {
        let box = self.box
        box.logQueue.sync { box.logHandler = level == .off ? nil : handler }
        let on = level != .off && handler != nil
        let boxPointer = Unmanaged.passUnretained(box).toOpaque()
        try retryingBusy {
            try Sipral.check(
                sipral_stack_log(
                    handle,
                    on ? level.rawValue : SipralLogLevel.off.rawValue,
                    on ? sipralLogTrampoline : nil,
                    on ? boxPointer : nil
                )
            )
        }
    }

    /// Everything this stack is holding, as the redacted text
    /// `sipral_stack_state` writes for a crash report: accounts, calls,
    /// transports, media sessions, the last refused calls, the queues, the
    /// RTP range and the counters. Safe from any thread, and never waits.
    public func state() throws -> String {
        var buffer = [CChar](repeating: 0, count: Sipral.stateTextMax)
        let length = try Sipral.stackState(stack: handle, buffer: &buffer)
        let bytes = buffer.prefix(max(0, length - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    #if canImport(os)
    /// Send this stack's log to the unified logging system: one `os.Logger`
    /// per target under `subsystem` -- category `call`, `sip`, `api` and so
    /// on (`docs/17-observability.md` lists the targets) -- so Console and
    /// `log stream --predicate 'subsystem == "org.sipral"'` filter by the
    /// part of the stack that wrote a line. The levels map as `.error` to
    /// `OSLogType.error`, `.warn` to `.default`, `.info` to `.info`, and
    /// `.debug` and `.trace` to `.debug` (`SipralLogLevel.osLogType`); a line
    /// that follows a flood says how many lines were turned away before it.
    /// Every line is already redacted by the stack, so it is logged as
    /// public: nothing reaches it that `<private>` would have hidden.
    /// `level` is the stack's own, and the unified logging system decides
    /// separately which of what arrives it keeps. Replaces whatever
    /// `setLog(level:handler:)` installed.
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

    /// This stack's health counters since it was created
    /// (`sipral_stack_counters`): registrations, how calls ended, what was
    /// screened, and -- new in ABI 0.30 -- requests and responses sent
    /// again, transactions timed out and requests refused at a limit. One
    /// struct copy, cheap enough to sample on a timer.
    public func counters() throws -> SipralCounters {
        SipralCounters(try retryingBusy { try Sipral.stackCounters(stack: handle) })
    }

    /// Ask these STUN servers from now on, in order of preference, each
    /// `host:port` -- what `stunServer` and `stunFallbacks` would have named
    /// -- without creating the stack again (`sipral_stack_stun_servers`).
    ///
    /// Every socket the stack keeps mapped is asked again of the new list at
    /// once: `SipralEventKind.stunServer` says the server in use moved and
    /// `.natMapping` what the new one answers. On a stack created without a
    /// STUN server the signalling socket starts being kept mapped, and every
    /// media socket opened from then on is asked where it appears from
    /// before its call is described. An empty list asks nobody any more:
    /// accounts a STUN answer moved register their own address again, and
    /// calls are described by their sockets' own addresses. A stack with a
    /// TURN server keeps asking STUN, so an empty list there throws
    /// `.invalidArgument`, as does an entry that is not an address and a
    /// port.
    public func setStunServers(_ servers: [String]) throws {
        let listed = servers.joined(separator: ",")
        try retryingBusy { try Sipral.stackStunServers(stack: handle, servers: listed, nowMs: nowMs()) }
        natQueue.sync { currentStunServer = servers.first }
    }

    /// `sipral_stack_stir`: verify the callers of the calls this stack's
    /// accounts receive against `anchors` (PEM or DER certificates, the
    /// STI-PA's roots in a SHAKEN deployment) from now on (RFC 8224),
    /// replacing what an earlier call set. `unixSeconds` is the wall clock
    /// now, which a PASSporT is signed and judged by, and defaults to this
    /// machine's; a stack whose accounts only sign calls this too, with no
    /// anchors, before adding them. The certificate a call names is asked for
    /// by `SipralEventKind.callerVerification` (`SipralEvent.verificationData`)
    /// and handed over with `stirCertificate(call:chain:)`.
    public func stir(
        anchors: [UInt8]?,
        freshnessSeconds: UInt64 = 0,
        certificateWaitMs: UInt64 = 0,
        unixSeconds: UInt64? = nil
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
            try retryingBusy { try Sipral.stackStir(stack: handle, config: config, nowMs: nowMs()) }
        }
    }

    /// `sipral_call_stir_certificate`: the chain the URL a verification asked
    /// for yielded -- PEM or DER, the signing certificate first -- or `nil`
    /// for one that could not be had. `call` is the handle the event named:
    /// the call has not been announced yet. Its verdict follows as
    /// `SipralEventKind.callerVerification` at `.verified`.
    public func stirCertificate(call: SipralHandle, chain: [UInt8]?) throws {
        try retryingBusy {
            try Sipral.callStirCertificate(stack: handle, call: call, chain: chain ?? [], nowMs: nowMs())
        }
    }

    /// Elapsed milliseconds since this stack was created -- what every entry
    /// point below expects `now_ms` to be.
    public func nowMs() -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- origin.uptimeNanoseconds) / 1_000_000
    }

    // MARK: - accounts and calls

    /// `sipral_account_add`.
    ///
    /// `sessionTimer` is how the account's calls ask for a session timer
    /// (RFC 4028): thirty minutes by default. `privacy` places every call
    /// anonymously (RFC 3323): `[.id]` is "withhold my number" -- `From`
    /// becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`, `Privacy`
    /// carries the values, and the account's own identity goes in
    /// `P-Asserted-Identity` only toward a trusted peer. `trustedPeers` are
    /// the IP addresses of the peers this account trusts -- usually the
    /// registrar or the trunk -- RFC 3325's trust domain: a call from one of
    /// them has its asserted identity read (`CallerIdentity`), from anywhere
    /// else it is left out, and once any are named no identity field leaves
    /// toward any other peer. `security` is the account's own SRTP policy
    /// and suites, and its STIR/SHAKEN verification and signing
    /// (`AccountSecurity`).
    public func addAccount(
        aor: String,
        registrarAddress: String,
        registrar: String? = nil,
        contact: String? = nil,
        displayName: String? = nil,
        authUser: String? = nil,
        authPassword: String? = nil,
        expiresSeconds: UInt64 = 0,
        sessionTimer: SessionTimer = .default,
        privacy: Privacy = [],
        trustedPeers: [String] = [],
        security: AccountSecurity = AccountSecurity()
    ) throws -> Account {
        let account = try Account.add(
            stack: self,
            aor: aor,
            registrarAddress: registrarAddress,
            registrar: registrar,
            contact: contact,
            displayName: displayName,
            authUser: authUser,
            authPassword: authPassword,
            expiresSeconds: expiresSeconds,
            sessionTimer: sessionTimer,
            privacy: privacy,
            trustedPeers: trustedPeers,
            security: security
        )
        movingQueue.sync { accounts[account.handle] = account }
        return account
    }

    func forgetAccount(_ account: SipralHandle) {
        movingQueue.sync { _ = accounts.removeValue(forKey: account) }
    }

    /// `sipral_call_place`, with this stack running the call's audio.
    ///
    /// A media socket is opened here, before the INVITE goes out; its
    /// `host:port` is what `sipral_call_config_t::media_address` offers, and
    /// `Call.media` mints once `SipralEventKind.mediaStarted` says the
    /// session is up.
    ///
    /// Take `Call.events()` as soon as this returns: the INVITE leaves on
    /// the poll thread's next pass, and an answer quicker than the caller
    /// is to take the stream is not replayed to it -- `Call.state`,
    /// `Call.media` and `Call.ended` still say where the call got to.
    ///
    /// With a `stunServer`, the media socket is first asked where it appears
    /// from, and this returns once the server has answered -- or has not,
    /// five and a half seconds on; with a TURN server, once the relay is
    /// allocated or refused as well. `takeIncomingCall` waits the same way.
    /// `ice` overrides the stack's own ICE policy for this call. `headers`
    /// go on the INVITE as written -- an `Alert-Info` asking for a
    /// distinctive ring, an `Answer-Mode` asking an intercom to pick up.
    public func placeCall(
        account: Account,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0,
        destination: String? = nil,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil,
        headers: [SipralHeader] = []
    ) throws -> Call {
        let mediaSocket = try openMediaSocket(host: mediaHost, port: mediaPort)
        let stackHandle = handle

        let callHandle: SipralHandle
        do {
            try mapMediaSocket(mediaSocket)
            let now = nowMs()
            callHandle = try CStrings.with([target, mediaSocket.localAddress, destination]) { parts in
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
                return try retryingBusy {
                    try Sipral.callPlace(
                        stack: stackHandle, account: account.handle, config: config, configHeaders: headers, nowMs: now
                    )
                }
            }
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }

        let call = Call(stack: self, handle: callHandle, mediaSocket: mediaSocket)
        registerCall(call)
        return call
    }

    /// Opens a media socket for an incoming call and answers it there.
    /// `event` is the `SipralEventKind.incomingCall` a listener read off
    /// `events()`. Call `rejectCall` instead when the application does not
    /// want it. The call's first events can arrive before the caller has
    /// taken `Call.events()`; `takeIncomingCall`, a stream, then
    /// `Call.answer()` is the order that misses none of them.
    public func answerCall(
        _ event: SipralEvent,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0
    ) throws -> Call {
        let call = try takeIncomingCall(event, mediaHost: mediaHost, mediaPort: mediaPort)
        try call.answer()
        return call
    }

    /// A `Call` for an incoming call that is left ringing: its media socket
    /// opened and its events routed, and nothing sent. `Call.answer()`
    /// answers it later, `Call.reject(code:)` refuses it.
    ///
    /// What an application that shows the call to a person first needs --
    /// on iOS, the `Call` bound into `CallKitBridge` before the user
    /// touches Answer, so that the `CXAnswerCallAction` CallKit then
    /// delivers is the one answer this call gets. `answerCall` is this
    /// plus the answer, for an agent that picks up at once.
    public func takeIncomingCall(
        _ event: SipralEvent,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0
    ) throws -> Call {
        let mediaSocket = try openMediaSocket(host: mediaHost, port: mediaPort)
        do {
            try mapMediaSocket(mediaSocket)
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }
        let call = Call(stack: self, handle: event.call, mediaSocket: mediaSocket, incoming: event.callData)
        registerCall(call)

        // The caller can have given up (CANCEL) between the poll thread
        // raising `incomingCall` and this running: its `callEnded` then
        // reached no `Call`, since none was registered yet, and this
        // handle is dead. A `Call` minted on it here would never observe
        // that end -- its streams would never finish, `ended` would stay
        // false, and a `CallKitBridge` bound to it would never report it
        // ended -- so the handle's liveness is checked right away. Any
        // failure to confirm it, stale handle or otherwise, closes and
        // forgets the call rather than handing back one this stack cannot
        // vouch for.
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

    /// Answer the `.incomingCall` `event` names with a 3xx instead of taking
    /// it: `Call.redirect(to:status:reason:)` for a call nothing has taken,
    /// which needs no media socket. 302 is call forwarding; `targets` are
    /// where to try, in order of preference; `reason` adds a `Diversion`.
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

    /// Who is calling, beyond the `From`, for the `.incomingCall` `event`
    /// names -- read before deciding whether to answer. See `CallerIdentity`.
    public func callerIdentity(of event: SipralEvent) throws -> CallerIdentity {
        try IdentityReader.identity(stack: self, call: event.call, data: event.callData)
    }

    /// How the `.incomingCall` `event` names asked to be answered and rung.
    public func answering(of event: SipralEvent) throws -> Answering {
        try IdentityReader.answering(stack: self, call: event.call, data: event.callData)
    }

    /// Take a REFER outside any dialog and place the call it asks for:
    /// `sipral_call_accept_transfer` on the referral's handle. `event` is the
    /// `SipralEventKind.referral` a listener read off `events()`, with a
    /// zero `referralData.statusCode`.
    ///
    /// The stack answers 202, reports on the call to whoever asked, and
    /// places it from the account the event names, to the REFER's own
    /// target -- never the caller's. A media socket is opened for it here,
    /// the way `placeCall` opens one, and the `Call` returned is that placed
    /// call. Whoever sent the REFER can make this line dial anything, so
    /// this is never done on the application's behalf.
    public func acceptReferral(
        _ event: SipralEvent,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil
    ) throws -> Call {
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

    /// Refuse a REFER outside any dialog with `code`, 300 to 699:
    /// `sipral_call_reject_transfer` on the referral's handle.
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

    /// How long `mapMediaSocket` waits: the STUN answer comes within five
    /// and a half seconds whatever the server does, and a TURN Allocate
    /// nobody answers is given up on after thirty-nine and a half.
    private var natPatience: DispatchTimeInterval {
        turnServer == nil ? .seconds(7) : .seconds(42)
    }

    /// `sipral_stack_nat_map` for a media socket about to carry a call, and
    /// the wait until the stack can describe the call by what the servers
    /// said -- placing or answering before that is
    /// `SIPRAL_STATUS_WRONG_STATE`. The socket is read by the poll thread
    /// from here until its call's media handle exists. Nothing at all on a
    /// stack without a STUN server.
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

    /// `mapMediaSocket` for the socket `Call.moveMedia` binds: where the
    /// STUN server sees it from, which the call is offered at, or `nil` on a
    /// stack without one.
    func mapMovedSocket(_ socket: UDPSocket) throws -> String? {
        try mapMediaSocket(socket)
    }

    /// The call's old socket is gone: `sipral_stack_nat_unmap`, so the stack
    /// stops refreshing a mapping nothing uses. Nothing on a stack without a
    /// STUN server.
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

    /// The call on `local` has its media handle: its socket's datagrams go
    /// to `sipral_media_receive` from now on, read by `Media`'s own thread.
    /// Called on the poll thread, in the same poll that raised
    /// `SipralEventKind.mediaStarted`.
    func mediaSocketTaken(_ local: String) {
        natQueue.sync { _ = stunSockets.removeValue(forKey: local) }
    }

    /// A media socket that will carry no call after all, or whose call ended
    /// before it had media: `sipral_stack_nat_unmap`, so the stack stops
    /// refreshing its mapping and gives its relay back, the Refresh that
    /// does that sent from the socket itself, and then the socket closed.
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

    /// `sipral_stack_poll_stun`: every request a media socket owes, sent
    /// from the socket the stack names -- the address the server sees it
    /// come from is the whole point -- to wherever the stack says: the
    /// STUN server, the TURN server, or, once a call is placed on a relay,
    /// the relay's refreshes. Its buffers are its own, since the poll thread
    /// and a thread giving a socket back can both be here.
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
                // for the TURN server, on the socket's connection to it:
                // never a datagram, which a network that blocks UDP drops
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

    /// Write `payload` on media socket `local`'s connection to the TURN
    /// server, whole: what `sipral_stack_poll_stun`,
    /// `sipral_stack_poll_farewell` and a call's media hand out marked TCP
    /// or TLS. Thread-safe.
    func writeTurn(_ local: String, _ payload: [UInt8]) {
        let connection = natQueue.sync { turnConnections[local] }
        connection?.send(payload)
    }

    /// Open or close what `SipralEventKind.turnStream` asked for in the poll
    /// that just ran, after this round's queues were written.
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

    /// Connect media socket `said.local` to the TURN server, and tell the
    /// stack how that went and everything the connection carries.
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

    /// What a connection carried, to `sipral_stack_turn_receive`: every
    /// byte, in order, since a stream that loses one never finds its place
    /// again, so a busy stack is waited for rather than skipped. A
    /// connection the stack found broken is closed and needs no word.
    private func turnReceived(_ local: String, _ bytes: [UInt8]) {
        while !isClosed {
            do {
                try Sipral.stackTurnReceive(stack: handle, local: local, data: bytes, nowMs: nowMs())
                return
            } catch let error as SipralError where error.status == .busy {
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

    /// Everything waiting on the media sockets not yet handed to a call's
    /// media, collected under `natQueue` and handed to
    /// `sipral_stack_receive_stun` outside it.
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

    /// The network the device is on, in as much detail as the stack's
    /// decision needs (`sipral_stack_network_changed`): the kind of link, the
    /// local address -- an IPv4 literal, no port -- the platform's own name
    /// for the interface, never parsed, and whether names resolve there.
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

    /// The address the stack's sockets are bound on now: the bind host, and
    /// after `networkChanged(to:)` the new network's.
    var currentHost: String {
        stateQueue.sync { network.address } ?? UDPSocket.parse(bindAddress).host
    }

    /// The platform said the network changed: `sipral_stack_network_changed`,
    /// and what its answer asks of the stack's own sockets.
    ///
    /// When the address or the interface changed -- `SipralRecovery.rebuild`
    /// -- the signalling socket is bound again at `to.address` and handed to
    /// the stack as its transport, and every account is pointed at it
    /// (`sipral_account_rebind`), so the REGISTER that follows names where
    /// this end is now. Every call up at the time then raises
    /// `SipralEventKind.callAddressWanted`: the far end is still sending its
    /// audio to the old address, and `Call.moveMedia()` offers it the new
    /// one. Anything less -- a roam that keeps the address -- only
    /// re-registers or re-proves, and moves nothing. Safe to call as often as
    /// the platform notifies; `.nothing` is most of the answers.
    @discardableResult
    public func networkChanged(to next: Network) throws -> SipralRecovery {
        try movingQueue.sync {
            let previous = stateQueue.sync { network }
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
            } else if moves {
                let host = next.address ?? UDPSocket.parse(bindAddress).host
                let fresh = try UDPSocket(host: host, port: 0)
                do {
                    // called directly: a datagram transport has no remote,
                    // which only a null pointer says, and the generated
                    // wrapper hands an empty string over as a real one
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
                    try account.rebind(local: rebound, previous: previous.address)
                }
            }
            return recovery
        }
    }

    /// Runs `body` with no network change half done: what `Call.moveMedia`
    /// holds while it binds and offers.
    func moving<T>(_ body: () throws -> T) throws -> T {
        try movingQueue.sync(execute: body)
    }

    // MARK: - the library's own audio engine

    /// A packet the engine encoded from the microphone, for `call`: sent from
    /// the call's media socket, or on its connection to a TURN server. On the
    /// engine's thread, which must not call back into the audio engine.
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
    /// `SipralEventKind.resolveNeeded` is passed on and not answered here.
    /// A dialog keeps the flow its INVITE went out on -- the registrar or
    /// outbound proxy an account names, the only path that survives a NAT
    /// -- and the event only says that the far end's `Contact` names some
    /// other address. This package has no resolver to answer it with, and
    /// answering with that `Contact` as a literal address moves the rest of
    /// the call onto it: behind a registrar reached through a port mapping
    /// or a NAT, the BYE then goes to an address nothing answers on. An
    /// application with a real lookup answers the event itself, through
    /// `Sipral.stackResolved`.
    fileprivate func handleEvent(_ raw: sipral_event_t) {
        let event = SipralEventDecoder.decode(raw)
        if let stream = event.turnStreamData {
            natQueue.sync { turnAsked.append(stream) }
        }
        noteNat(event)
        if let call = callFor(event.call) {
            call.deliver(event)
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
            if signalling != .udp {
                // one connection carries everything, whatever it names: the
                // server it reaches is the outbound proxy
                signallingQueue.sync { link }?.send(payload)
                continue
            }
            let destination = transmitDestination.withMemoryRebound(to: UInt8.self, capacity: transmit.destination_len) {
                String(decoding: UnsafeBufferPointer(start: $0, count: transmit.destination_len), as: UTF8.self)
            }
            signallingQueue.sync { _ = socket?.send(payload, to: destination) }
        }
    }

    /// `sipral_stack_poll_farewell`: what a call that just ended still owes
    /// -- its RTCP BYE, and with a TURN server the Refresh that gives its
    /// relay back -- sent through that call's own media socket to the
    /// address the stack names. Under ICE that is the path ICE chose or the
    /// TURN server, not necessarily the last address media came from, which
    /// is only the fallback for a packet that names none.
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
                    guard let call = try? Sipral.stackPollFarewell(stack: handle, outPacket: &packet),
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
                // given back on the relay's connection, which is the
                // stack's and not the call's, and outlives it
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
            // The signalling socket first, then every media socket still
            // waiting for its call's media handle.
            // over TCP or TLS there is no signalling socket: the connection
            // has a reader of its own, and a descriptor of -1 is one poll
            // leaves alone
            let signalling = signallingQueue.sync { socket }
            var pfds = [pollfd(fd: signalling?.fd ?? -1, events: Int16(POLLIN), revents: 0)]
            pfds += stunDescriptors.map { pollfd(fd: $0, events: Int16(POLLIN), revents: 0) }
            _ = pfds.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 50) }
            if pfds.dropFirst().contains(where: { $0.revents & Int16(POLLIN) != 0 }) {
                receiveStun()
            }
            if let signalling, pfds[0].revents & Int16(POLLIN) != 0 {
                let local = signalling.localAddress
                while let (data, from) = signallingQueue.sync(execute: {
                    socket === signalling ? signalling.receive() : nil
                }) {
                    // `to` is "the address the datagram arrived on"
                    // (`docs/08-ffi.md`) and null/empty is meant to mean
                    // this stack's own bind address, for "a socket bound to
                    // one address" -- which is always this socket, so it is
                    // passed explicitly: `SipralAbi.swift`'s generated
                    // `stackReceiveDatagram` takes `to` as a non-optional
                    // `String` and builds its C pointer from
                    // `Array(to.utf8)`, whose `baseAddress` for an empty
                    // array is not the null pointer
                    // `sipral_stack_receive_datagram` reads "take my own
                    // bind address" from, so an empty string here would be
                    // refused rather than treated as absent. Bytes that are
                    // not a message are refused the same way a public SIP
                    // port refuses one -- logged nowhere in this layer, and
                    // not fatal to the poll loop.
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
        }
        closedSemaphore.signal()
    }

    private var isClosed: Bool { stateQueue.sync { closed } }

    /// `sipral_stack_destroy`, and everything this wrapper opened.
    ///
    /// Whatever calls are still open are hung up first, while the poll
    /// thread can still send what that queues and while each call is still
    /// tracked and its media socket still open -- `Call.close()` only runs
    /// afterwards, once the poll thread has had a round to drain both the
    /// hangups just queued and the farewells they leave behind
    /// (`bindings/python/sipral/stack.py`'s `close` explains why the order
    /// matters).
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
        // and every connection to the TURN server still open: what it
        // carried was given back through it above, or lapses with it
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
        try? Sipral.stackDestroy(stack: handle)
        eventBroadcast.finish()
        signallingQueue.sync { socket?.close() }
    }
}

/// Waits out `SIPRAL_STATUS_BUSY` the way
/// `bindings/python/sipral/errors.py`'s `call()` does: "Signalling on one
/// stack is one thread at a time, and a second thread is told so rather
/// than made to wait" (`docs/08-ffi.md`) is a promise about the C ABI, not
/// something an application should have to retry by hand for the ordinary
/// case of the poll thread and a caller arriving at the same moment.
func retryingBusy<T>(_ body: () throws -> T) throws -> T {
    let deadline = DispatchTime.now() + 0.5
    while true {
        do {
            return try body()
        } catch let error as SipralError where error.status == .busy {
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

/// `sipral_stack_log`'s callback: runs on whichever thread has just let the
/// stack go, with nothing of the library held, one line at a time.
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

/// `audio_transmit_callback`: runs on the library's audio engine thread,
/// once per packet per call, with the packet valid only until it returns --
/// so it is copied out here, and nothing in it calls the audio engine back.
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
