// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral
import Dispatch

/// What a `SipralEventKind.conferenceChanged` carries
/// (`sipral_conference_event_t`): a notification about a conference was
/// merged, or the focus deleted it. `SipralSubscription.conference()` reads the
/// picture it left.
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

/// What a `SipralEventKind.presenceChanged` carries
/// (`sipral_presence_event_t`). For `.watched`, a presentity a `presence`
/// subscription watches: `basic`, `activity`, `entity` and `note`. For
/// `.publication`, this account's own published presence, the event's
/// `account`: `publicationState`, `failure`, `statusCode`, `expiresMs` and
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

/// This account's presence as `Account.publishPresence(_:)` publishes it
/// (RFC 3903, a PIDF document for the address of record): reachable or not,
/// what the person is doing (`.none` publishes no person at all; `.other`
/// has no name to publish under and is refused), and a note a buddy list
/// shows beside the name, on one line.
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

/// One subscription (RFC 6665): `Account.subscribe(to:package:)`,
/// `Account.watchPresence(of:)` or `Call.subscribeConference()`.
///
/// The stack keeps it -- refreshes it, subscribes again after a notifier's
/// `deactivated` -- until `end()`; what it learns arrives on
/// `SipralStack.events()`: `SipralEventKind.subscriptionChanged` and
/// `.notified` for every package, `.presenceChanged` for `presence` and
/// `.conferenceChanged` for `conference`, each naming this `handle`.
///
/// Named with the package's prefix, as `SipralStack` and `SipralEvent` are,
/// because a bare `Subscription` is also Combine's protocol: a file that
/// imports both would have to spell out which it means at every use.
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

    /// `sipral_subscription_end`: unsubscribe (`Expires: 0`) and let the
    /// handle go once the notifier's last word is in.
    public func end() throws {
        try retryingBusy { try Sipral.subscriptionEnd(stack: stack.handle, subscription: handle, nowMs: stack.nowMs()) }
    }

    /// The conference this subscription holds, read whole: `nil` for one
    /// to another package, and for one no document has reached yet.
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

/// The name `SipralSubscription` had until the package prefixed it, which
/// Combine's `Subscription` collides with. Kept for one minor release.
@available(*, deprecated, renamed: "SipralSubscription")
public typealias Subscription = SipralSubscription

/// A recording session to a recording server (SIPREC, RFC 7866), from
/// `Call.record(toServer:destination:host:)`.
///
/// It is a call of its own on the stack -- `handle` is the one its
/// `SipralEventKind.callConfirmed` and `.callEnded` name on
/// `SipralStack.events()` -- kept in step with the recorded call by the
/// stack: the metadata follows a hold or a transfer, and it ends when the
/// recorded call does. The copies of both parties' audio leave from two
/// sockets of their own, `thisEnd` (what this end sent, the stream labelled
/// `1`) and `farEnd` (what it heard, labelled `2`).
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

    /// `sipral_call_stop_recording_to`: the copies stop at once and the
    /// recording session is hung up. `.wrongState` once nothing records the
    /// call any more.
    public func stop() throws {
        try call.stopRecordingToServer()
    }
}

/// Reads one piece of text the ABI copies into a caller's buffer, with a
/// buffer large enough for any the library holds, and a second, larger one
/// for the rare piece that is not.
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
