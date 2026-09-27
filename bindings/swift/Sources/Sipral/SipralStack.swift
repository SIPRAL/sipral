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
    public let bindAddress: String

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

    private let socket: UDPSocket
    private let origin: DispatchTime
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
    }

    /// The STUN server this stack asks where its sockets appear from, as
    /// `host:port`, or `nil` for a stack that asks nobody.
    public let stunServer: String?
    private let turnServer: String?

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
    /// relay under ICE. `g729AnnexB` allows G.729's silence compression
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
    public init(
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
        registrarKeepaliveMs: UInt64 = 0
    ) throws {
        let socket = try UDPSocket(host: bindHost, port: bindPort)
        self.socket = socket
        self.bindAddress = socket.localAddress
        self.stunServer = stunServer
        self.turnServer = turn?.address
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
                    [socket.localAddress, userAgent, codecs, stunServer, turn?.address, turn?.username, turn?.password]
                ) { parts in
                    var config = sipral_stack_config_t.sized()
                    config.event_callback = sipralStackEventTrampoline
                    config.event_user_data = boxPointer
                    config.transport = SipralTransport.udp.rawValue
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
                    if let stunPointer = parts[3].pointer {
                        config.nat = SipralNat.stun.rawValue
                        config.stun_server = stunPointer
                        config.stun_server_len = parts[3].count
                    }
                    if let turnPointer = parts[4].pointer {
                        config.turn_server = turnPointer
                        config.turn_server_len = parts[4].count
                        config.turn_username = parts[5].pointer
                        config.turn_username_len = parts[5].count
                        config.turn_password = parts[6].pointer
                        config.turn_password_len = parts[6].count
                    }
                    return try Sipral.stackCreate(config: config)
                }
            }
        }

        box.stack = self
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.run() }
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

    /// Elapsed milliseconds since this stack was created -- what every entry
    /// point below expects `now_ms` to be.
    public func nowMs() -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- origin.uptimeNanoseconds) / 1_000_000
    }

    // MARK: - accounts and calls

    public func addAccount(
        aor: String,
        registrarAddress: String,
        registrar: String? = nil,
        contact: String? = nil,
        displayName: String? = nil,
        authUser: String? = nil,
        authPassword: String? = nil,
        expiresSeconds: UInt64 = 0
    ) throws -> Account {
        try Account.add(
            stack: self,
            aor: aor,
            registrarAddress: registrarAddress,
            registrar: registrar,
            contact: contact,
            displayName: displayName,
            authUser: authUser,
            authPassword: authPassword,
            expiresSeconds: expiresSeconds
        )
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
    /// `ice` overrides the stack's own ICE policy for this call.
    public func placeCall(
        account: Account,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0,
        destination: String? = nil,
        srtp: SipralSrtp? = nil,
        ice: SipralIce? = nil
    ) throws -> Call {
        let mediaSocket = try UDPSocket(host: mediaHost, port: mediaPort)
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
                        stack: stackHandle, account: account.handle, config: config, configHeaders: [], nowMs: now
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
        let mediaSocket = try UDPSocket(host: mediaHost, port: mediaPort)
        do {
            try mapMediaSocket(mediaSocket)
        } catch {
            giveBackMediaSocket(mediaSocket)
            throw error
        }
        let call = Call(stack: self, handle: event.call, mediaSocket: mediaSocket)
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
        let mediaSocket = try UDPSocket(host: mediaHost, port: mediaPort)
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
    private func mapMediaSocket(_ socket: UDPSocket) throws {
        guard stunServer != nil else { return }
        let local = socket.localAddress
        let waiter = NatWaiter(needsRelay: turnServer != nil)
        natQueue.sync {
            stunSockets[local] = socket
            natWaiters[local] = waiter
        }
        defer { natQueue.sync { _ = natWaiters.removeValue(forKey: local) } }
        try retryingBusy { try Sipral.stackNatMap(stack: handle, local: local, nowMs: nowMs()) }
        _ = waiter.done.wait(timeout: .now() + natPatience)
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
            if event.natData != nil { waiter.mapped = true } else { waiter.relayed = true }
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
            let taken: (payload: [UInt8], destination: String, source: String)? = data.withUnsafeMutableBufferPointer { dataBuf in
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
                            String(decoding: sourceBuf.prefix(transmit.source_len), as: UTF8.self)
                        )
                    }
                }
            }
            guard let taken else { return }
            natQueue.sync { _ = stunSockets[taken.source]?.send(taken.payload, to: taken.destination) }
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
            let destination = transmitDestination.withMemoryRebound(to: UInt8.self, capacity: transmit.destination_len) {
                String(decoding: UnsafeBufferPointer(start: $0, count: transmit.destination_len), as: UTF8.self)
            }
            socket.send(payload, to: destination)
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
            let taken: (call: SipralHandle, payload: [UInt8], destination: String)? =
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
                        String(decoding: destinationBuf.prefix(packet.destination_len), as: UTF8.self)
                    )
                }
            guard let taken else { return }
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
            var pfds = [pollfd(fd: socket.fd, events: Int16(POLLIN), revents: 0)]
            pfds += stunDescriptors.map { pollfd(fd: $0, events: Int16(POLLIN), revents: 0) }
            _ = pfds.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 50) }
            if pfds.dropFirst().contains(where: { $0.revents & Int16(POLLIN) != 0 }) {
                receiveStun()
            }
            if pfds[0].revents & Int16(POLLIN) != 0 {
                while let (data, from) = socket.receive() {
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
                        to: bindAddress, nowMs: nowMs()
                    )
                }
            }
            guard (try? Sipral.stackPoll(stack: handle, nowMs: nowMs())) != nil else { continue }
            drainTransmit()
            drainStun()
            drainFarewells()
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
        try? Sipral.stackDestroy(stack: handle)
        eventBroadcast.finish()
        socket.close()
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
