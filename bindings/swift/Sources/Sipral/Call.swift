// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral
import Dispatch

/// A `sipral_handle_t` naming one call, and the actions it takes.
///
/// Built by `SipralStack.placeCall` for one this stack placed, and by
/// `SipralStack.answerCall` for one that came in; either way it is
/// registered with its stack before the caller ever sees it, so `deliver`
/// always has somewhere to put an event that names this call
/// (`bindings/python/sipral/call.py`'s `Call` is the same shape).
public final class Call: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle

    /// How many events, or digits, one reader of `events()` or `dtmf()` holds
    /// unread before it starts dropping its oldest -- the same bound, and the
    /// same choice of what to drop, as the Kotlin layer's `SipralCall.events`.
    public static let eventBuffer = 4096

    private let eventBroadcast = Broadcast<SipralEvent>(
        label: "org.sipral.call.events", policy: .bufferingNewest(Call.eventBuffer)
    )
    private let dtmfBroadcast = Broadcast<Character>(
        label: "org.sipral.call.dtmf", policy: .bufferingNewest(Call.eventBuffer)
    )

    /// A new reader of every event this call's handle names, decoded whole.
    ///
    /// Every call returns a stream of its own, and every stream gets every
    /// event, in the order the stack raised them: a `CallKitBridge` bound to
    /// this call and the application's own loop over it both see all of
    /// them. A reader sees what arrives from the moment this returns, and
    /// nothing before -- so take the stream first and act second:
    /// `let events = call.events()`, then `try call.hold()`, then wait on
    /// `events`. What a late reader missed that still matters can be read
    /// directly: `media` is set before `SipralEventKind.mediaStarted` is
    /// delivered, `ended` before `SipralEventKind.callEnded`.
    ///
    /// Every stream finishes when the call ends, right after its
    /// `SipralEventKind.callEnded`, or when `close()` runs first. A reader
    /// that starts after the end gets that `callEnded` event alone and
    /// finishes at once, so `for await` over a fresh stream always ends.
    /// `SipralEventKind.mediaStatistics`, which comes after `callEnded`,
    /// reaches the stack's `SipralStack.events()` only.
    ///
    /// Each reader buffers on its own, up to `Call.eventBuffer` events; one
    /// that falls further behind drops its own oldest, and never slows the
    /// others. A reader that stops -- its loop left, its task cancelled --
    /// is fed nothing more.
    public func events() -> AsyncStream<SipralEvent> {
        eventBroadcast.stream()
    }

    /// A new reader of just the digits: `SipralEventKind.digitReceived`'s
    /// own `mediaData.digit`, so a voice agent that only cares about DTMF
    /// does not have to filter `events()` itself. The same rules as
    /// `events()`: every reader gets every digit from the moment it asks,
    /// and every stream finishes when the call ends, with no digit replayed
    /// to a reader that starts after that.
    public func dtmf() -> AsyncStream<Character> {
        dtmfBroadcast.stream()
    }

    /// How many readers of `events()` are still being fed -- `internal` for
    /// the same reason as `debugMediaSocketDescriptor`.
    var debugEventReaders: Int { eventBroadcast.readerCount }

    private let stateQueue = DispatchQueue(label: "org.sipral.call.state")
    private var _media: Media?
    private var _ended = false
    private var _closed = false

    public var media: Media? {
        stateQueue.sync { _media }
    }

    private func setMedia(_ media: Media) {
        stateQueue.sync { _media = media }
    }

    public var ended: Bool {
        stateQueue.sync { _ended }
    }

    /// The socket the call was placed or answered on: until `media` exists it
    /// is the call's, and from then on `Media` owns it -- and whichever
    /// socket `moveMedia` puts in its place.
    private let mediaSocket: UDPSocket
    private var _mediaAddress: String
    /// The call's media socket, as `host:port`: the name
    /// `sipral_stack_nat_map` gave it, and so of its connection to a TURN
    /// server reached over TCP or TLS; after `moveMedia`, the new one.
    var mediaAddress: String { stateQueue.sync { _mediaAddress } }

    /// The `.incomingCall` this call was taken from, for `identity()` and
    /// `answering()`; `nil` for a call this end placed.
    private let incoming: CallEventData?

    /// The raw descriptor `close()` releases on the no-media path -- `internal`
    /// rather than `private` only so `SipralTests` can watch it directly, the
    /// way a white-box concurrency test has to; nothing outside this module
    /// reads it, so the public surface this package exposes is unchanged.
    var debugMediaSocketDescriptor: Int32 { mediaSocket.fd }

    init(stack: SipralStack, handle: SipralHandle, mediaSocket: UDPSocket, incoming: CallEventData? = nil) {
        self.stack = stack
        self.handle = handle
        self.mediaSocket = mediaSocket
        self._mediaAddress = mediaSocket.localAddress
        self.incoming = incoming
    }

    /// Writes to this call's media socket -- used by `SipralStack` for what
    /// `sipral_stack_poll_farewell` hands back once signalling has already
    /// ended, and for the packets the library's engine encodes in device
    /// mode. Through `media` once it exists, which owns the socket then.
    func sendOnMediaSocket(_ payload: [UInt8], to address: String) {
        if let media {
            media.sendDatagram(payload, to: address)
        } else {
            mediaSocket.send(payload, to: address)
        }
    }

    /// Called by `SipralStack` on its own poll thread.
    ///
    /// Every side effect below -- minting `media`, marking `ended` -- happens
    /// before `event` is ever handed to a reader: a task already awaiting
    /// `events()` that wakes and reads `call.media` must see it already set
    /// (`bindings/python/sipral/call.py`'s `deliver` orders its own steps
    /// for the same reason).
    func deliver(_ event: SipralEvent) {
        if event.kindRaw == SipralEventKind.mediaStarted.rawValue, media == nil {
            // Behind a NAT the poll thread has been reading this socket for
            // the stack until now; from the media handle on, `Media` does.
            stack.mediaSocketTaken(mediaAddress)
            if let minted = try? Media(
                stack: stack, callHandle: handle, socket: mediaSocket, pumpsFrames: !stack.audioMode.isDevice
            ) {
                setMedia(minted)
            }
        }
        if event.kindRaw == SipralEventKind.callEnded.rawValue {
            stateQueue.sync { _ended = true }
            eventBroadcast.finish(after: event)
            dtmfBroadcast.finish()
            return
        }
        eventBroadcast.send(event)
        if event.kindRaw == SipralEventKind.digitReceived.rawValue, let digit = event.mediaData?.digit {
            dtmfBroadcast.send(digit)
        }
    }

    // MARK: - state

    /// `sipral_call_state`, read fresh -- not cached from the last event,
    /// which a status query between events would otherwise miss.
    public var state: SipralCallState? {
        get throws {
            let raw = try retryingBusy { try Sipral.callState(stack: stack.handle, call: handle) }
            return SipralCallState(rawValue: raw)
        }
    }

    // MARK: - actions

    /// `sipral_call_answer_media`: accept, with this stack running the audio
    /// through the media socket this call already opened.
    public func answer() throws {
        try retryingBusy {
            try Sipral.callAnswerMedia(
                stack: stack.handle, call: handle, mediaAddress: mediaAddress, nowMs: stack.nowMs()
            )
        }
    }

    /// `sipral_call_reject`: 486 Busy Here, 603 Decline, or whatever
    /// response code fits.
    public func reject(code: UInt32 = 486) throws {
        try retryingBusy {
            try Sipral.callReject(stack: stack.handle, call: handle, code: code, nowMs: stack.nowMs())
        }
    }

    public func hangup() throws {
        try retryingBusy {
            try Sipral.callHangup(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_hangup_for`: end the call as `hangup()` does, and say
    /// why with a `Reason` (RFC 3326) on the BYE, or on the CANCEL a call
    /// still ringing turns into. A call that came in and was never answered
    /// is refused with only the Q.850 value (RFC 6432): a SIP one would
    /// repeat the refusal's own status.
    public func hangup(reason: HangupReason) throws {
        try retryingBusy {
            try Sipral.callHangupFor(
                stack: stack.handle, call: handle, sipCause: reason.sipCause ?? 0,
                q850Cause: reason.q850Cause ?? 0, text: reason.text ?? "", nowMs: stack.nowMs()
            )
        }
    }

    /// `sipral_call_redirect`: answer a call that came in, and is still
    /// ringing, with a 3xx (RFC 3261 §21.3) naming where to try instead, in
    /// order of preference -- 302 is call forwarding. `reason` -- `no-answer`,
    /// `user-busy`, `unconditional`, `deflection`, `do-not-disturb` or any
    /// other token -- adds a `Diversion` (RFC 5806) naming the address that
    /// was called.
    public func redirect(to targets: [String], status: UInt32 = 302, reason: String? = nil) throws {
        try stack.redirect(call: handle, to: targets, status: status, reason: reason)
    }

    /// Who is calling, beyond the `From`: for a call that came in, what the
    /// network asserted behind the account's trust gate, the caller's
    /// `Privacy` and where the call was diverted from. Empty for a call this
    /// end placed.
    public func identity() throws -> CallerIdentity {
        try IdentityReader.identity(stack: stack, call: handle, data: incoming)
    }

    /// How a call that came in asked to be answered (RFC 5373) and rung
    /// (`Alert-Info`).
    public func answering() throws -> Answering {
        try IdentityReader.answering(stack: stack, call: handle, data: incoming)
    }

    /// Offer this call at a socket on the network the device is on now:
    /// what `SipralEventKind.callAddressWanted` asks for once
    /// `SipralStack.networkChanged(to:)` has said the old one is gone.
    ///
    /// A socket is bound at `host` -- the new network's address,
    /// `SipralStack.networkChanged(to:)`'s own by default -- asked where it
    /// appears from when the stack has a STUN server, and the call offered
    /// there with `sipral_call_media_readdress`: a re-INVITE with only `c=`
    /// and the port moved (RFC 3264 §8.3.1), carrying the account's new
    /// `Contact`. The new socket carries the call from then on, whatever the
    /// far end answers; the answer arrives as `.sessionChanged`, a refusal as
    /// `.sessionChangeFailed`. A call under ICE is refused with
    /// `.wrongState`: `restartIce()` moves it.
    public func moveMedia(host: String? = nil, port: UInt16 = 0) throws {
        try stack.moving {
            guard let media else {
                throw SipralError(status: .wrongState, message: "the call has no media to move yet")
            }
            let fresh = try stack.openMediaSocket(host: host ?? stack.currentHost, port: port)
            do {
                let publicAddress = try stack.mapMovedSocket(fresh)
                try retryingBusy {
                    try Sipral.callMediaReaddress(
                        stack: stack.handle, call: handle, mediaAddress: fresh.localAddress,
                        publicAddress: publicAddress ?? "", nowMs: stack.nowMs()
                    )
                }
            } catch {
                stack.giveBackMediaSocket(fresh)
                throw error
            }
            let old = media.localAddress
            stack.mediaSocketTaken(fresh.localAddress)
            stack.forgetMapping(old)
            media.replaceSocket(with: fresh)
            stateQueue.sync { _mediaAddress = fresh.localAddress }
        }
    }

    public func hold() throws {
        try retryingBusy {
            try Sipral.callHold(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    public func resume() throws {
        try retryingBusy {
            try Sipral.callResume(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    /// `sipral_call_restart_ice`: offer the call again with new ICE
    /// credentials (RFC 8445 §9) and check every pair again once the far end
    /// answers, while the path it has carries the audio -- the remedy for a
    /// path whose consent was lost, and for a network change. The new path
    /// arrives as another `.mediaPathChosen`.
    public func restartIce() throws {
        try retryingBusy {
            try Sipral.callRestartIce(stack: stack.handle, call: handle, nowMs: stack.nowMs())
        }
    }

    public func sendDtmf(_ digits: String, via: SipralDtmf = .rtp, durationMs: UInt32 = 100) throws {
        try retryingBusy {
            try Sipral.callSendDtmf(
                stack: stack.handle, call: handle, digits: digits, via: via.rawValue,
                durationMs: durationMs, nowMs: stack.nowMs()
            )
        }
    }

    /// Hang up if this call is still up, release its media, forget it.
    /// Idempotent, and safe to call regardless of how the call ended --
    /// including two callers racing to close the same call, such as a
    /// `CALL_ENDED` event handler and a user action landing at once, which
    /// is exactly the shape `stateQueue` guards `Media.close()` and
    /// `SipralStack.close()` against elsewhere in this layer. Without the
    /// guard, a second, concurrent call here that finds `media` still `nil`
    /// -- a call closed before its media ever started -- would close
    /// `mediaSocket`'s file descriptor a second time, which POSIX does not
    /// make safe: a fresh, unrelated socket opened by another thread in
    /// between can already hold that same descriptor number by then.
    public func close() {
        let wasClosed = stateQueue.sync { () -> Bool in
            defer { _closed = true }
            return _closed
        }
        guard !wasClosed else { return }

        if !ended {
            try? hangup()
        }
        if let media {
            media.close()
        } else {
            stack.giveBackMediaSocket(mediaSocket)
        }
        stack.forgetCall(handle)
        eventBroadcast.finish()
        dtmfBroadcast.finish()
    }
}
