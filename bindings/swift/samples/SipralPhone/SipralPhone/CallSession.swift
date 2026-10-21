// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
import Sipral

/// One call on screen: the stack's `Call`, the system's UUID for it when
/// CallKit shows it, and its audio once media has started.
@MainActor
final class CallSession: ObservableObject, Identifiable {
    let id = UUID()
    let call: Call
    /// CallKit's identifier, `nil` when the system does not show the call.
    let uuid: UUID?
    let remote: String
    let outgoing: Bool
    let placedAt: Date

    @Published var state = "calling"
    @Published var confirmedAt: Date?
    @Published var muted = false
    @Published var held = false
    @Published var speaker = false
    @Published var route = ""
    @Published var audioState = "idle"
    @Published var statistics = ""
    @Published var digits = ""

    var audio: CallAudio?
    var observer: AudioSessionObserver?
    var tasks: [Task<Void, Never>] = []

    init(call: Call, uuid: UUID?, remote: String, outgoing: Bool, placedAt: Date = Date()) {
        self.call = call
        self.uuid = uuid
        self.remote = remote
        self.outgoing = outgoing
        self.placedAt = placedAt
    }

    /// Lets go of everything the session holds; the call itself is the
    /// stack's to end.
    func finish() {
        for task in tasks {
            task.cancel()
        }
        tasks = []
        observer?.cancel()
        observer = nil
        audio?.close()
        audio = nil
    }
}

/// A call ringing in the application's own screen, where CallKit does not
/// show it (the simulator).
struct IncomingOffer: Identifiable {
    let id = UUID()
    let event: SipralEvent
    let caller: String
}

/// The account a push meets, readable from PushKit's queue.
final class AccountBox: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Account?

    var account: Account? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return current
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            current = newValue
        }
    }
}
