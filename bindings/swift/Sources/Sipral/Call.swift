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

    /// Every event this call's handle names, decoded whole.
    public let events: AsyncStream<SipralEvent>
    private let eventContinuation: AsyncStream<SipralEvent>.Continuation

    /// Just the digits: `SipralEventKind.digitReceived`'s own
    /// `mediaData.digit`, so a voice agent that only cares about DTMF does
    /// not have to filter `events` itself.
    public let dtmf: AsyncStream<Character>
    private let dtmfContinuation: AsyncStream<Character>.Continuation

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

    private let mediaSocket: UDPSocket
    private let mediaAddress: String

    /// The raw descriptor `close()` releases on the no-media path -- `internal`
    /// rather than `private` only so `SipralTests` can watch it directly, the
    /// way a white-box concurrency test has to; nothing outside this module
    /// reads it, so the public surface this package exposes is unchanged.
    var debugMediaSocketDescriptor: Int32 { mediaSocket.fd }

    init(stack: SipralStack, handle: SipralHandle, mediaSocket: UDPSocket) {
        self.stack = stack
        self.handle = handle
        self.mediaSocket = mediaSocket
        self.mediaAddress = mediaSocket.localAddress

        var eventContinuation: AsyncStream<SipralEvent>.Continuation!
        self.events = AsyncStream { eventContinuation = $0 }
        self.eventContinuation = eventContinuation

        var dtmfContinuation: AsyncStream<Character>.Continuation!
        self.dtmf = AsyncStream { dtmfContinuation = $0 }
        self.dtmfContinuation = dtmfContinuation
    }

    /// Called by `SipralStack` on its own poll thread.
    ///
    /// Every side effect below -- minting `media`, marking `ended` -- happens
    /// before `event` is ever yielded to a consumer: a task already awaiting
    /// `events` that wakes and reads `call.media` must see it already set
    /// (`bindings/python/sipral/call.py`'s `deliver` orders its own steps
    /// for the same reason).
    func deliver(_ event: SipralEvent) {
        if event.kindRaw == SipralEventKind.mediaStarted.rawValue, media == nil,
           let minted = try? Media(stack: stack, callHandle: handle, socket: mediaSocket) {
            setMedia(minted)
        }
        if event.kindRaw == SipralEventKind.callEnded.rawValue {
            stateQueue.sync { _ended = true }
        }
        eventContinuation.yield(event)
        if event.kindRaw == SipralEventKind.digitReceived.rawValue, let digit = event.mediaData?.digit {
            dtmfContinuation.yield(digit)
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
            mediaSocket.close()
        }
        stack.forgetCall(handle)
        eventContinuation.finish()
        dtmfContinuation.finish()
    }
}
