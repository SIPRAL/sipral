// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral

/// One event, copied out of `sipral_event_t` while it was still live.
///
/// `sipral_event_t`'s pointers -- `message`, an SDP, a URI -- are valid only
/// for the length of the C callback that carries it, and never after
/// (`docs/08-ffi.md`, "Signalling across the boundary"). So every byte a
/// caller might want later is copied out here, once, synchronously, on the
/// thread `sipral_stack_poll` is running on; what crosses into the
/// `AsyncStream` afterwards is a plain, `Sendable`, ordinary value that owns
/// what it holds.
public struct SipralEvent: Sendable {
    /// The raw `sipral_event_kind_t`. Present even for a kind this build's
    /// `SipralEventKind` does not have a case for yet, because a header
    /// newer than the Swift package it is paired with must still be able to
    /// report it (`kindName` is `sipral_event_kind_name`'s own answer, and
    /// stays current the same way).
    public let kindRaw: UInt32
    public let kind: SipralEventKind?
    public let kindName: String
    public let stack: SipralHandle
    public let account: SipralHandle
    public let call: SipralHandle
    public let message: [UInt8]?
    public let callData: CallEventData?
    public let mediaData: MediaEventData?
    public let registrationData: RegistrationEventData?
    public let announceData: AnnounceEventData?
    /// `payload.nat`, for `SipralEventKind.natMapping` only.
    public let natData: NatEventData?
    /// `payload.relay`, for `SipralEventKind.natRelay` only.
    public let relayData: RelayEventData?
}

/// What a STUN server said about one of this stack's sockets
/// (`sipral_nat_event_t`).
public struct NatEventData: Sendable {
    public let mappingRaw: UInt32
    public let mapping: SipralNatMapping?
    /// True for the signalling socket, false for a call's media socket.
    public let signalling: Bool
    /// The transport, for the signalling socket; zero otherwise.
    public let transport: UInt32
    /// How many accounts' `Contact` moved to `mapped` because of this.
    public let accounts: UInt32
    /// The socket, as this layer bound it.
    public let local: String
    /// Where the server saw it from -- the public address -- or `nil` for
    /// `SipralNatMapping.unanswered`.
    public let mapped: String?
    /// The mapping before, for `SipralNatMapping.moved`.
    public let previous: String?
}

/// What a TURN server said about a media socket's relay
/// (`sipral_nat_relay_event_t`). Nothing of the credential is in it.
public struct RelayEventData: Sendable {
    public let outcomeRaw: UInt32
    public let outcome: SipralNatRelay?
    /// The STUN error code the server refused with, or zero.
    public let code: UInt32
    public let local: String
    /// The relayed address, for `SipralNatRelay.allocated`.
    public let relayed: String?
    public let mapped: String?
    /// Why there is none, for `SipralNatRelay.failed`.
    public let reason: String?
}

public struct CallEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralCallState?
    public let endReasonRaw: UInt32
    public let endReason: SipralCallEndReason?
    public let statusCode: UInt32
    public let other: SipralHandle
    public let heldHere: Bool
    public let heldThere: Bool
    public let localSdp: [UInt8]?
    public let remoteSdp: [UInt8]?
    public let retryInMs: UInt64
    public let fromUri: String?
    public let fromDisplay: String?
    public let toUri: String?
    public let callId: String?
    public let digit: UInt32
}

public struct MediaEventData: Sendable {
    public let codec: UInt32
    public let direction: UInt32
    public let silentForMs: UInt64
    public let recordedMs: UInt64
    public let fault: UInt32
    public let reason: String?
    /// `sipral_media_event_t::digit`, as the character it names, or `nil`
    /// for every kind but `SipralEventKind.digitReceived`.
    public let digit: Character?
    public let eventCode: UInt32
    public let heldMs: UInt64
    public let suite: UInt32
    public let sourceRaw: UInt32
    public let source: SipralDigitSource?
}

public struct RegistrationEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralRegistrationState?
    public let failure: UInt32
    public let statusCode: UInt32
    public let expiresMs: UInt64
    public let refreshInMs: UInt64
    public let retryInMs: UInt64
}

public struct AnnounceEventData: Sendable {
    public let announcement: SipralHandle
    public let waitedMs: UInt64
}

enum SipralEventDecoder {
    // Kinds whose payload lives in `payload.call` (`sipral_call_event_t`),
    // mirroring `bindings/python/sipral/events.py`'s `_CALL_KINDS`.
    private static let callKinds: Set<UInt32> = [
        SipralEventKind.incomingCall.rawValue,
        SipralEventKind.callProgress.rawValue,
        SipralEventKind.callForked.rawValue,
        SipralEventKind.callConfirmed.rawValue,
        SipralEventKind.sessionChanged.rawValue,
        SipralEventKind.sessionOffered.rawValue,
        SipralEventKind.sessionChangeFailed.rawValue,
        SipralEventKind.callReplaced.rawValue,
        SipralEventKind.callEnded.rawValue,
        SipralEventKind.dtmfSent.rawValue,
    ]

    // Kinds whose payload lives in `payload.media` (`sipral_media_event_t`).
    private static let mediaKinds: Set<UInt32> = [
        SipralEventKind.mediaStatistics.rawValue,
        SipralEventKind.mediaStalled.rawValue,
        SipralEventKind.mediaStarted.rawValue,
        SipralEventKind.mediaChanged.rawValue,
        SipralEventKind.mediaResumed.rawValue,
        SipralEventKind.mediaFailed.rawValue,
        SipralEventKind.recordingStopped.rawValue,
        SipralEventKind.digitReceived.rawValue,
        SipralEventKind.mediaSecured.rawValue,
        SipralEventKind.mediaPathChosen.rawValue,
    ]

    private static func bytes(_ pointer: UnsafePointer<UInt8>?, _ length: Int) -> [UInt8]? {
        guard let pointer, length > 0 else { return nil }
        return Array(UnsafeBufferPointer(start: pointer, count: length))
    }

    private static func text(_ pointer: UnsafePointer<UInt8>?, _ length: Int) -> String? {
        guard let raw = bytes(pointer, length) else { return nil }
        return String(decoding: raw, as: UTF8.self)
    }

    private static func textC(_ pointer: UnsafePointer<CChar>?, _ length: Int) -> String? {
        guard let pointer, length > 0 else { return nil }
        return pointer.withMemoryRebound(to: UInt8.self, capacity: length) { text($0, length) }
    }

    private static func callData(_ call: sipral_call_event_t) -> CallEventData {
        CallEventData(
            stateRaw: call.state,
            state: SipralCallState(rawValue: call.state),
            endReasonRaw: call.end_reason,
            endReason: SipralCallEndReason(rawValue: call.end_reason),
            statusCode: call.status_code,
            other: call.other,
            heldHere: call.held_here != 0,
            heldThere: call.held_there != 0,
            localSdp: bytes(call.local_sdp, call.local_sdp_len),
            remoteSdp: bytes(call.remote_sdp, call.remote_sdp_len),
            retryInMs: call.retry_in_ms,
            fromUri: text(call.from_uri, call.from_uri_len),
            fromDisplay: text(call.from_display, call.from_display_len),
            toUri: text(call.to_uri, call.to_uri_len),
            callId: text(call.call_id, call.call_id_len),
            digit: call.digit
        )
    }

    private static func mediaData(_ media: sipral_media_event_t) -> MediaEventData {
        let digitChar: Character?
        if media.digit != 0, let scalar = Unicode.Scalar(media.digit) {
            digitChar = Character(scalar)
        } else {
            digitChar = nil
        }
        return MediaEventData(
            codec: media.codec,
            direction: media.direction,
            silentForMs: media.silent_for_ms,
            recordedMs: media.recorded_ms,
            fault: media.fault,
            reason: textC(media.reason, media.reason_len),
            digit: digitChar,
            eventCode: media.event_code,
            heldMs: media.held_ms,
            suite: media.suite,
            sourceRaw: media.source,
            source: SipralDigitSource(rawValue: media.source)
        )
    }

    private static func registrationData(_ registration: sipral_registration_event_t) -> RegistrationEventData {
        RegistrationEventData(
            stateRaw: registration.state,
            state: SipralRegistrationState(rawValue: registration.state),
            failure: registration.failure,
            statusCode: registration.status_code,
            expiresMs: registration.expires_ms,
            refreshInMs: registration.refresh_in_ms,
            retryInMs: registration.retry_in_ms
        )
    }

    private static func announceData(_ announce: sipral_announce_event_t) -> AnnounceEventData {
        AnnounceEventData(announcement: announce.announcement, waitedMs: announce.waited_ms)
    }

    private static func natData(_ nat: sipral_nat_event_t) -> NatEventData {
        NatEventData(
            mappingRaw: nat.mapping,
            mapping: SipralNatMapping(rawValue: nat.mapping),
            signalling: nat.signalling != 0,
            transport: nat.transport,
            accounts: nat.accounts,
            local: textC(nat.local, nat.local_len) ?? "",
            mapped: textC(nat.mapped, nat.mapped_len),
            previous: textC(nat.previous, nat.previous_len)
        )
    }

    private static func relayData(_ relay: sipral_nat_relay_event_t) -> RelayEventData {
        RelayEventData(
            outcomeRaw: relay.outcome,
            outcome: SipralNatRelay(rawValue: relay.outcome),
            code: relay.code,
            local: textC(relay.local, relay.local_len) ?? "",
            relayed: textC(relay.relayed, relay.relayed_len),
            mapped: textC(relay.mapped, relay.mapped_len),
            reason: textC(relay.reason, relay.reason_len)
        )
    }

    /// Copies one `sipral_event_t` out into a standalone `SipralEvent`.
    ///
    /// Called from inside the C callback, and nowhere else: `raw` points at
    /// memory the callback's own caller owns, and every field this reads is
    /// read before this function returns.
    static func decode(_ raw: sipral_event_t) -> SipralEvent {
        let kindRaw = raw.kind
        let kindName = String(cString: sipral_event_kind_name(kindRaw))
        var callData: CallEventData?
        var mediaData: MediaEventData?
        var registrationData: RegistrationEventData?
        var announceData: AnnounceEventData?
        var natData: NatEventData?
        var relayData: RelayEventData?

        if kindRaw == SipralEventKind.natMapping.rawValue {
            natData = self.natData(raw.payload.nat)
        } else if kindRaw == SipralEventKind.natRelay.rawValue {
            relayData = self.relayData(raw.payload.relay)
        } else if kindRaw == SipralEventKind.registrationChanged.rawValue {
            registrationData = self.registrationData(raw.payload.registration)
        } else if callKinds.contains(kindRaw) {
            callData = self.callData(raw.payload.call)
        } else if mediaKinds.contains(kindRaw) {
            mediaData = self.mediaData(raw.payload.media)
        } else if kindRaw == SipralEventKind.callAnnounced.rawValue
            || kindRaw == SipralEventKind.announcedCallMissing.rawValue {
            announceData = self.announceData(raw.payload.announce)
        }

        return SipralEvent(
            kindRaw: kindRaw,
            kind: SipralEventKind(rawValue: kindRaw),
            kindName: kindName,
            stack: raw.stack,
            account: raw.account,
            call: raw.call,
            message: bytes(raw.message, raw.message_len),
            callData: callData,
            mediaData: mediaData,
            registrationData: registrationData,
            announceData: announceData,
            natData: natData,
            relayData: relayData
        )
    }
}
