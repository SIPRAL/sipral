// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
#if canImport(Security)
import Security
#endif
#if canImport(UIKit) && os(iOS)
import UIKit
#endif

/// Where `SipralAppLifecycle` keeps each account's written-down
/// registration between processes. `KeychainSnapshotStore` on Apple
/// platforms; anything else that keeps bytes private to the application.
public protocol SipralSnapshotStore: AnyObject, Sendable {
    func read(_ key: String) throws -> [UInt8]?
    /// `nil` removes it.
    func write(_ value: [UInt8]?, for key: String) throws
}

/// A store refused to read or write, with the platform's status.
public struct SipralSnapshotStoreError: Error, Sendable, Equatable {
    public let status: Int32
}

#if canImport(Security)
/// Generic passwords under one service in the Keychain, readable after the
/// first unlock (a push may start the process while the phone is locked)
/// and never carried to another device by a backup.
public final class KeychainSnapshotStore: SipralSnapshotStore, @unchecked Sendable {
    private let service: String

    public init(service: String = "org.sipral.registration") {
        self.service = service
    }

    private func query(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    public func read(_ key: String) throws -> [UInt8]? {
        var request = query(key)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var found: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &found)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = found as? Data else { throw SipralSnapshotStoreError(status: status) }
        return Array(data)
    }

    public func write(_ value: [UInt8]?, for key: String) throws {
        let removed = SecItemDelete(query(key) as CFDictionary)
        guard removed == errSecSuccess || removed == errSecItemNotFound else {
            throw SipralSnapshotStoreError(status: removed)
        }
        guard let value else { return }
        var item = query(key)
        item[kSecValueData as String] = Data(value)
        #if os(iOS)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw SipralSnapshotStoreError(status: added) }
    }
}
#endif

/// Ties a stack to the application's lifecycle on a device that suspends
/// and ends processes (`docs/15-mobile.md`, "C3", and `docs/16-lifecycle.md`).
///
/// Into the background with no call up, every kept account's registration
/// is written down (`Account.freeze()`) into the store, **then** the stack
/// is told it is suspending: once told, a binding no longer counts as
/// bound and there would be nothing to write. With a call up, iOS keeps the
/// process running and nothing is done. Back in the foreground, the stack
/// is told it resumed.
///
/// A launch, a push's included, calls `launched(_:)` as soon as the stack
/// exists, then adds each account and `restore(_:key:)`s it before deciding
/// to register: a restored account reads `.restored`, continues its
/// registrar's binding with the same `Call-ID` and sequence, and the push's
/// own refresh (`PushKitBridge.handle`) confirms it, with no new
/// registration for the registrar to hold beside the old one.
public final class SipralAppLifecycle: @unchecked Sendable {
    private let store: SipralSnapshotStore
    private let clock: @Sendable () -> UInt64
    private let stateQueue = DispatchQueue(label: "org.sipral.lifecycle.state")
    private var kept: [String: Account] = [:]
    private var _stack: SipralStack?
    private var observers: [(center: NotificationCenter, token: NSObjectProtocol)] = []

    /// A snapshot that could not be written, read or used; the stack
    /// carries on either way.
    public var storageFailed: (@Sendable (Error) -> Void)?

    /// `clock` is the wall clock in Unix milliseconds: how long a snapshot
    /// slept is only measurable by one that runs while the process does not.
    public init(store: SipralSnapshotStore, clock: @escaping @Sendable () -> UInt64 = SipralAppLifecycle.unixMs) {
        self.store = store
        self.clock = clock
    }

    public static let unixMs: @Sendable () -> UInt64 = {
        UInt64(max(0, Date().timeIntervalSince1970 * 1000))
    }

    /// The stack the lifecycle is applied to.
    public var stack: SipralStack? {
        get { stateQueue.sync { _stack } }
        set { stateQueue.sync { _stack = newValue } }
    }

    /// The process started, a push's launch included: `stack` is applied
    /// to and its cold start declared, the zero of `timeToReadyMs()`.
    public func launched(_ stack: SipralStack) throws {
        self.stack = stack
        try stack.coldStart()
    }

    /// Writes `account`'s registration down under `key` on every move to
    /// the background. The key names the account across processes.
    public func keep(_ account: Account, key: String) {
        stateQueue.sync { kept[key] = account }
    }

    /// Stops keeping `key` and removes what was written: for an account the
    /// user removed or changed.
    public func forget(key: String) {
        stateQueue.sync { _ = kept.removeValue(forKey: key) }
        try? store.write(nil, for: Self.storeKey(key))
    }

    /// Reads back what was written under `key` onto `account`, added and
    /// not yet registered, and keeps it from now on. `false` when nothing
    /// usable was there; the application then calls `register()`.
    @discardableResult
    public func restore(_ account: Account, key: String) -> Bool {
        keep(account, key: key)
        let stored: [UInt8]?
        do {
            stored = try store.read(Self.storeKey(key))
        } catch {
            storageFailed?(error)
            return false
        }
        guard let (writtenAt, snapshot) = stored.flatMap(Self.record(from:)) else { return false }
        let now = clock()
        do {
            try account.thaw(snapshot, asleepMs: now > writtenAt ? now - writtenAt : 0)
            return true
        } catch {
            storageFailed?(error)
            try? store.write(nil, for: Self.storeKey(key))
            return false
        }
    }

    /// The application is entering the background. Returns what the stack
    /// reported, or `nil` when there is no stack or a call is up.
    @discardableResult
    public func enteredBackground() -> SipralSuspended? {
        let (stack, accounts) = stateQueue.sync { (_stack, kept) }
        guard let stack else { return nil }
        if stack.callsUp > 0 {
            return nil
        }
        let now = clock()
        for (key, account) in accounts {
            write(key: key, account: account, now: now)
        }
        do {
            return try stack.suspending()
        } catch {
            storageFailed?(error)
            return nil
        }
    }

    /// The application is back in the foreground.
    public func enteredForeground() {
        try? stack?.resumed()
    }

    #if canImport(UIKit) && os(iOS)
    /// Follows `UIApplication`'s background and foreground notifications,
    /// for an application that does not call the two itself.
    public func observeApplication(center: NotificationCenter = .default) {
        let tokens = [
            center.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) {
                [weak self] _ in self?.enteredBackground()
            },
            center.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) {
                [weak self] _ in self?.enteredForeground()
            },
        ]
        stateQueue.sync { observers += tokens.map { (center, $0) } }
    }
    #endif

    deinit {
        for observer in observers {
            observer.center.removeObserver(observer.token)
        }
    }

    private func write(key: String, account: Account, now: UInt64) {
        let snapshot: [UInt8]
        do {
            snapshot = try account.freeze()
        } catch let refused as SipralError where refused.status == .wrongState {
            try? store.write(nil, for: Self.storeKey(key))
            return
        } catch {
            storageFailed?(error)
            return
        }
        do {
            try store.write(Self.record(writtenAt: now, snapshot: snapshot), for: Self.storeKey(key))
        } catch {
            storageFailed?(error)
        }
    }

    static func storeKey(_ key: String) -> String { "sipral.registration.\(key)" }

    /// When it was written, eight bytes big-endian of Unix milliseconds,
    /// then the opaque snapshot.
    static func record(writtenAt: UInt64, snapshot: [UInt8]) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: writtenAt >> (56 - 8 * UInt64($0))) } + snapshot
    }

    static func record(from bytes: [UInt8]) -> (writtenAt: UInt64, snapshot: [UInt8])? {
        guard bytes.count > 8 else { return nil }
        let writtenAt = bytes.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        return (writtenAt, Array(bytes.dropFirst(8)))
    }
}
