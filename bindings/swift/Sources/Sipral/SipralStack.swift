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
/// and the transport queues around it, and the `AsyncStream` events land on
/// -- the layer `SipralAbi.swift` (printed by `tools/abi-gen` from
/// `crates/sipral-ffi`) is written against directly, the way
/// `bindings/python/sipral/stack.py`'s `Stack` is the same shape in Python
/// (`docs/08-ffi.md`, "Swift").
///
/// **Threading.** The C callback (`docs/08-ffi.md`, "Events arrive on one
/// callback") lands on this stack's own poll thread and is decoded there,
/// synchronously, into a `Sendable` `SipralEvent` before it ever reaches
/// `events`: nothing past that point touches the pointers `sipral_event_t`
/// only promises for the length of the callback. `events` is a Swift
/// `AsyncStream`, and `Continuation.yield` is documented safe to call from
/// any thread, which is what lets the poll thread feed it directly with no
/// further hop. Every other member here that calls into the C ABI may be
/// called from any thread the application likes; a collision with the poll
/// thread already inside the stack's lock is `SIPRAL_STATUS_BUSY` and is
/// retried for up to half a second before it is thrown (`docs/08-ffi.md`,
/// "Signalling on one stack is one thread at a time").
public final class SipralStack: @unchecked Sendable {
    public let handle: SipralHandle
    public let bindAddress: String

    /// Every event this stack raises, decoded whole. A consumer that wants
    /// only one call's events reads `Call.events` instead.
    public let events: AsyncStream<SipralEvent>
    private let eventContinuation: AsyncStream<SipralEvent>.Continuation

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

    public init(
        bindHost: String = "127.0.0.1",
        bindPort: UInt16 = 0,
        userAgent: String? = nil,
        codecs: String? = nil,
        frameMs: UInt32 = 0,
        offerDtmf: Bool? = nil,
        srtp: SipralSrtp? = nil
    ) throws {
        let socket = try UDPSocket(host: bindHost, port: bindPort)
        self.socket = socket
        self.bindAddress = socket.localAddress
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
                try CStrings.with([socket.localAddress, userAgent, codecs]) { parts in
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
                    return try Sipral.stackCreate(config: config)
                }
            }
        }

        var continuation: AsyncStream<SipralEvent>.Continuation!
        self.events = AsyncStream { continuation = $0 }
        self.eventContinuation = continuation

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
    public func placeCall(
        account: Account,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0,
        destination: String? = nil,
        srtp: SipralSrtp? = nil
    ) throws -> Call {
        let mediaSocket = try UDPSocket(host: mediaHost, port: mediaPort)
        let stackHandle = handle
        let now = nowMs()

        let callHandle: SipralHandle = try CStrings.with([target, mediaSocket.localAddress, destination]) { parts in
            var config = sipral_call_config_t.sized()
            config.target = parts[0].pointer
            config.target_len = parts[0].count
            config.media_address = parts[1].pointer
            config.media_address_len = parts[1].count
            config.srtp = srtp?.rawValue ?? 0
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

        let call = Call(stack: self, handle: callHandle, mediaSocket: mediaSocket)
        registerCall(call)
        return call
    }

    /// Opens a media socket for an incoming call and answers it there.
    /// `event` is the `SipralEventKind.incomingCall` a listener read off
    /// `events`. Call `rejectCall` instead when the application does not
    /// want it.
    public func answerCall(
        _ event: SipralEvent,
        mediaHost: String = "127.0.0.1",
        mediaPort: UInt16 = 0
    ) throws -> Call {
        let mediaSocket = try UDPSocket(host: mediaHost, port: mediaPort)
        let call = Call(stack: self, handle: event.call, mediaSocket: mediaSocket)
        registerCall(call)
        try call.answer()
        return call
    }

    public func rejectCall(_ event: SipralEvent, code: UInt32 = 486) throws {
        try retryingBusy {
            try Sipral.callReject(stack: handle, call: event.call, code: code, nowMs: nowMs())
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

    // MARK: - the poll thread

    fileprivate func handleEvent(_ raw: sipral_event_t) {
        let event = SipralEventDecoder.decode(raw)
        if event.kindRaw == SipralEventKind.resolveNeeded.rawValue {
            resolve(raw: raw)
        }
        if let call = callFor(event.call) {
            call.deliver(event)
        }
        eventContinuation.yield(event)
    }

    /// Answers `SipralEventKind.resolveNeeded` with the host as given.
    ///
    /// This package wires no DNS resolver of its own (`docs/08-ffi.md`
    /// leaves RFC 3263 lookup to the caller on purpose); the numeric
    /// `host:port` targets this layer is built around never raise it in the
    /// first place, so this is only reached by a caller that named a
    /// registrar or a target by hostname. An application that wants a real
    /// lookup answers the event itself, through `Sipral.stackResolved`.
    private func resolve(raw: sipral_event_t) {
        let resolveEvent = raw.payload.resolve
        guard let hostPointer = resolveEvent.host, resolveEvent.host_len > 0 else { return }
        let hostText = hostPointer.withMemoryRebound(to: UInt8.self, capacity: resolveEvent.host_len) {
            String(decoding: UnsafeBufferPointer(start: $0, count: resolveEvent.host_len), as: UTF8.self)
        }
        let port = resolveEvent.port == 0 ? 5060 : resolveEvent.port
        let address = "\(hostText):\(port)"
        try? Sipral.stackResolved(
            stack: handle, dialog: resolveEvent.dialog, addresses: address, protocol: resolveEvent.protocol
        )
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

    /// `sipral_stack_poll_farewell`: the RTCP BYE a call that just ended
    /// still owes, sent through that call's own media socket, to the last
    /// address media was actually heard from.
    private func drainFarewells() {
        while true {
            var packet = sipral_media_packet_t.sized()
            packet.data = farewellData
            packet.capacity = 1500
            packet.destination = nil
            packet.destination_capacity = 0
            let call: SipralHandle
            do {
                call = try Sipral.stackPollFarewell(stack: handle, outPacket: &packet)
            } catch {
                return
            }
            guard packet.len > 0 else { return }
            guard let target = callFor(call), let media = target.media, let remote = media.remoteAddress else {
                continue
            }
            let payload = Array(UnsafeBufferPointer(start: farewellData, count: packet.len))
            media.sendRaw(payload, to: remote)
        }
    }

    private func run() {
        while !isClosed {
            var pfd = pollfd(fd: socket.fd, events: Int16(POLLIN), revents: 0)
            _ = withUnsafeMutablePointer(to: &pfd) { poll($0, 1, 50) }
            if pfd.revents & Int16(POLLIN) != 0 {
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

        _ = closedSemaphore.wait(timeout: .now() + 5)
        try? Sipral.stackDestroy(stack: handle)
        eventContinuation.finish()
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
