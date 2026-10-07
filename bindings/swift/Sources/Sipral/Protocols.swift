// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral
import Dispatch

/// What `SipralEventKind.conferenceChanged` carries; read the result with
/// `SipralSubscription.conference()`.
public struct ConferenceEventData: Sendable {
    /// Which subscription it is about.
    public let subscription: SipralHandle
    /// Merged, or the conference ended (and the subscription is given up).
    public let update: SipralConferenceUpdate?
    /// The version of the document the picture is at now; zero once the
    /// conference ended.
    public let version: UInt32
    /// How many users the picture holds.
    public let users: UInt32
}

/// What a `SipralEventKind.textReceived` carries (`sipral_text_event_t`):
/// what the far end typed (RFC 4103), with a REPLACEMENT CHARACTER where a
/// block was lost and no redundant copy recovered it.
public struct TextEventData: Sendable, Equatable {
    public let text: String
    /// How many blocks were lost that way.
    public let missing: UInt32
}

/// What `SipralEventKind.presenceChanged` carries. `.watched` fills `basic`,
/// `activity`, `entity` and `note`; `.publication` (our own) fills
/// `publicationState`, `failure`, `statusCode`, `expiresMs` and
/// `refreshInMs`.
public struct PresenceEventData: Sendable {
    public let kind: SipralPresenceKind?
    /// The subscription, for `.watched`; `Sipral.handleNone` for a
    /// publication.
    public let subscription: SipralHandle
    public let basic: SipralBasic?
    public let activity: SipralActivity?
    public let entity: String?
    public let note: String?
    public let publicationState: SipralPublicationState?
    public let failure: SipralPublishFailure?
    /// The status the compositor answered with, when one did.
    public let statusCode: UInt32
    /// The lifetime granted, when it was published.
    public let expiresMs: UInt64
    /// How long until the stack refreshes it.
    public let refreshInMs: UInt64
}

/// Presence for `Account.publishPresence(_:)` (RFC 3903, PIDF). Activity
/// `.none` publishes no person; `.other` is refused. `note` is one line.
public struct Presence: Sendable, Equatable {
    public var basic: SipralBasic
    public var activity: SipralActivity
    public var note: String?

    public init(basic: SipralBasic, activity: SipralActivity = .none, note: String? = nil) {
        self.basic = basic
        self.activity = activity
        self.note = note
    }
}

/// One user of a conference, as the focus described it (RFC 4575 §5.6).
public struct ConferenceUser: Sendable, Equatable {
    /// The address of record it takes part as.
    public let entity: String
    public let displayText: String
    /// The `entity` of its first endpoint: the device it is on.
    public let endpoint: String
    /// How many endpoints -- devices -- it is in the conference from.
    public let endpoints: UInt32
    /// Where the first of them is.
    public let status: SipralEndpointStatus
    /// How many media streams the first of them has.
    public let media: UInt32
}

/// A conference as a `conference` subscription holds it: every document the
/// focus sent, merged (RFC 4575 §4.6). A piece the focus never sent is an
/// empty string, a flag it never sent `nil`.
public struct Conference: Sendable, Equatable {
    /// The version of the last document merged.
    public let version: UInt32
    /// The conference's URI.
    public let entity: String
    public let subject: String
    public let displayText: String
    /// How many users the focus says it counts, which may be more than
    /// `users` lists.
    public let userCount: UInt32?
    public let active: Bool?
    public let locked: Bool?
    /// Every user, in the order the focus first named them.
    public let users: [ConferenceUser]
}

/// One subscription (RFC 6665).
///
/// The stack refreshes it, and resubscribes after `deactivated`, until
/// `end()`. Updates arrive on `SipralStack.events()` naming `handle`:
/// `subscriptionChanged` and `.notified`, plus `.presenceChanged` or
/// `.conferenceChanged` for those packages. Prefixed to avoid Combine's
/// `Subscription`.
public final class SipralSubscription: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle
    /// The event package, as the SUBSCRIBE named it.
    public let package: String

    init(stack: SipralStack, handle: SipralHandle, package: String) {
        self.stack = stack
        self.handle = handle
        self.package = package
    }

    /// `sipral_subscription_state`, read fresh.
    public var state: SipralSubscriptionState? {
        get throws {
            let raw = try retryingBusy { try Sipral.subscriptionState(stack: stack.handle, subscription: handle) }
            return SipralSubscriptionState(rawValue: raw)
        }
    }

    /// `sipral_subscription_end`: unsubscribe (`Expires: 0`); the handle
    /// goes after the final NOTIFY.
    public func end() throws {
        try retryingBusy { try Sipral.subscriptionEnd(stack: stack.handle, subscription: handle, nowMs: stack.nowMs()) }
    }

    /// The merged conference; `nil` for other packages or before any NOTIFY.
    public func conference() throws -> Conference? {
        let whole: sipral_conference_t
        do {
            whole = try retryingBusy { try Sipral.subscriptionConference(stack: stack.handle, subscription: handle) }
        } catch let error as SipralError where error.status == .notSupported {
            return nil
        }
        let users = try (0..<Int(whole.users)).map { index -> ConferenceUser in
            let user = try retryingBusy {
                try Sipral.subscriptionConferenceUserAt(stack: stack.handle, subscription: handle, index: index)
            }
            return ConferenceUser(
                entity: try text(.userEntity, index),
                displayText: try text(.userDisplayText, index),
                endpoint: try text(.userEndpoint, index),
                endpoints: user.endpoints,
                status: SipralEndpointStatus(rawValue: user.status) ?? .unknown,
                media: user.media
            )
        }
        return Conference(
            version: whole.version,
            entity: try text(.entity, 0),
            subject: try text(.subject, 0),
            displayText: try text(.displayText, 0),
            userCount: whole.has_user_count != 0 ? whole.user_count : nil,
            active: Self.flag(whole.active),
            locked: Self.flag(whole.locked),
            users: users
        )
    }

    /// `conference-state`'s tri-state: one said yes, two said no.
    private static func flag(_ raw: UInt32) -> Bool? {
        switch raw {
        case 1: return true
        case 2: return false
        default: return nil
        }
    }

    private func text(_ which: SipralConferenceText, _ index: Int) throws -> String {
        try ProtocolText.read { buffer in
            try retryingBusy {
                try Sipral.subscriptionConferenceText(
                    stack: stack.handle, subscription: handle, index: index, which: which.rawValue, buffer: &buffer
                )
            }
        }
    }
}

/// Former name of `SipralSubscription`. Kept for one minor release.
@available(*, deprecated, renamed: "SipralSubscription")
public typealias Subscription = SipralSubscription

/// A recording session to a recording server (SIPREC, RFC 7866), from
/// `Call.record(toServer:destination:host:)`.
///
/// A call of its own (`handle` appears in `callConfirmed`/`callEnded`), kept
/// in step with the recorded call and ended with it. Audio copies leave
/// from `thisEnd` (label `1`) and `farEnd` (label `2`).
public final class RecordingSession: @unchecked Sendable {
    public let handle: SipralHandle
    /// The socket this end's audio is copied from, `host:port`.
    public let thisEnd: String
    /// The socket the far end's audio is copied from.
    public let farEnd: String
    private unowned let call: Call

    init(handle: SipralHandle, thisEnd: String, farEnd: String, call: Call) {
        self.handle = handle
        self.thisEnd = thisEnd
        self.farEnd = farEnd
        self.call = call
    }

    /// `sipral_call_stop_recording_to`: stop now and hang up the session.
    /// `.wrongState` if already stopped.
    public func stop() throws {
        try call.stopRecordingToServer()
    }
}

/// Reads ABI text into a buffer, retrying once with a larger one.
enum ProtocolText {
    static func read(_ fill: (inout [CChar]) throws -> Int) throws -> String {
        for capacity in [1024, 65536] {
            var buffer = [CChar](repeating: 0, count: capacity)
            do {
                let needed = try fill(&buffer)
                let length = max(needed - 1, 0)
                return String(decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            } catch let error as SipralError where error.status == .bufferTooSmall && capacity < 65536 {
                continue
            }
        }
        return ""
    }
}
