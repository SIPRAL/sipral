// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// What was standing when the stack was told it is suspending
/// (`SipralStack.suspending()`). Past tense: nothing was sent about any of
/// it.
public struct SipralSuspended: Sendable, Equatable {
    /// Bindings that read as live and are no longer believed.
    public let unverified: Int
    /// Subscriptions whose last notification stopped being evidence.
    public let subscriptions: Int
    /// Calls that were up, left as they are.
    public let calls: Int

    init(_ raw: sipral_suspending_t) {
        unverified = raw.unverified
        subscriptions = raw.subscriptions
        calls = raw.calls
    }
}

extension SipralStack {
    /// `sipral_stack_suspending`: the system is about to stop this process
    /// (on iOS, the scene entering the background with no call up). Nothing
    /// is sent and nothing stays scheduled; calls are left alone
    /// (`docs/16-lifecycle.md`).
    @discardableResult
    public func suspending() throws -> SipralSuspended {
        SipralSuspended(try retryingBusy { try Sipral.stackSuspending(stack: handle, nowMs: nowMs()) })
    }

    /// `sipral_stack_resumed`: the process runs again. Every binding is
    /// proved again before it is believed; safe without a `suspending()`
    /// before it.
    public func resumed() throws {
        try retryingBusy { try Sipral.stackResumed(stack: handle, nowMs: nowMs()) }
    }

    /// `sipral_stack_cold_start`: now is when the user started waiting, the
    /// zero of every account's `timeToReadyMs()`. Called again, it clears
    /// and restarts each measurement.
    public func coldStart() throws {
        try retryingBusy { try Sipral.stackColdStart(stack: handle, nowMs: nowMs()) }
    }

    /// `sipral_stack_interface_lost`: no interface is usable. Nothing is
    /// tried until `networkChanged(to:)` reports one back.
    public func interfaceLost() throws {
        try retryingBusy { try Sipral.stackInterfaceLost(stack: handle, nowMs: nowMs()) }
    }

    /// `sipral_stack_name_resolution_lost`: names no longer become
    /// addresses. Bindings whose registrar is a name stop being believed;
    /// those aimed at a literal address keep running.
    public func nameResolutionLost() throws {
        try retryingBusy { try Sipral.stackNameResolutionLost(stack: handle, nowMs: nowMs()) }
    }
}

extension Account {
    /// `sipral_account_freeze`: the registration written down, to carry
    /// into a later process with `thaw(_:asleepMs:)`. The bytes are opaque
    /// and name the address of record, so store them where the password
    /// would go. Throws `.wrongState` when there is nothing worth keeping:
    /// never registered, failed, or given up.
    public func freeze() throws -> [UInt8] {
        var capacity = 512
        while true {
            var buffer = [UInt8](repeating: 0, count: capacity)
            do {
                let length = try retryingBusy {
                    try Sipral.accountFreeze(stack: stack.handle, account: handle, buffer: &buffer, nowMs: stack.nowMs())
                }
                return Array(buffer.prefix(length))
            } catch let error as SipralError where error.status == .bufferTooSmall {
                capacity *= 4
            }
        }
    }

    /// `sipral_account_thaw`: a registration `freeze()` wrote, read back
    /// into this account, added and not yet registered. `asleepMs` is how
    /// long the snapshot sat unused, by the wall clock. The account reads
    /// `.restored` until a registrar confirms it, and its next REGISTER
    /// continues the same `Call-ID` and sequence. Refused, with the account
    /// unchanged: `.unsupportedVersion` for a newer build's bytes,
    /// `.notSupported` for an account that does not register,
    /// `.invalidArgument` for bytes that are no snapshot or another
    /// account's.
    public func thaw(_ snapshot: [UInt8], asleepMs: UInt64) throws {
        try retryingBusy {
            try Sipral.accountThaw(
                stack: stack.handle, account: handle, snapshot: snapshot, asleepMs: asleepMs, nowMs: stack.nowMs()
            )
        }
        wantsRegistrationAgain()
    }

    /// `sipral_account_time_to_ready`: how long after `coldStart()` this
    /// account became reachable, or `nil` before it has (or with no cold
    /// start declared).
    public func timeToReadyMs() throws -> UInt64? {
        let answer = try retryingBusy { try Sipral.accountTimeToReady(stack: stack.handle, account: handle) }
        return answer.hasValue != 0 ? answer.ms : nil
    }
}
