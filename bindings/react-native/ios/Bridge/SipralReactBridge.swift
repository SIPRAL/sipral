// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralReactCore as Objective-C sees it: dictionaries in, and each call
// settled through the resolve and reject blocks a React Native promise is,
// on one serial queue -- so the calls JavaScript makes reach the stack in the
// order it made them, and none of them waits on the JavaScript thread.

import Foundation

@objc(SipralReactBridge)
public final class SipralReactBridge: NSObject {
    public typealias Resolve = (Any?) -> Void
    public typealias Reject = (String, String, Error?) -> Void

    private let core: SipralReactCore
    private let queue = DispatchQueue(label: "org.sipral.react-native")

    /// `emit` is handed each event, flattened, as the spec's NativeEvent.
    @objc public init(emit: @escaping @Sendable ([String: Any]) -> Void) {
        core = SipralReactCore(emit: emit)
    }

    init(core: SipralReactCore) {
        self.core = core
    }

    @objc public func open(_ options: [String: Any], resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.open(SipralOpenOptions(options)) }
    }

    @objc public func close(resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { self.core.close() }
    }

    @objc public func addAccount(_ options: [String: Any], resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.addAccount(SipralAccountOptions(options)) }
    }

    @objc public func register(_ account: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.register(account) }
    }

    @objc public func unregister(_ account: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.unregister(account) }
    }

    @objc public func setAccessToken(
        _ account: String, token: String, resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) { try self.core.setAccessToken(account, token: token) }
    }

    @objc public func removeAccount(_ account: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.removeAccount(account) }
    }

    @objc public func placeCall(
        _ account: String, target: String, options: [String: Any],
        resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) {
            try self.core.placeCall(
                account, target,
                destination: options["destination"] as? String, codecs: options["codecs"] as? String
            )
        }
    }

    @objc public func answer(
        _ call: String, options: [String: Any], resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) { try self.core.answer(call, codecs: options["codecs"] as? String) }
    }

    @objc public func reject(_ call: String, code: Int, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.reject(call, code: code) }
    }

    @objc public func hangup(_ call: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.hangup(call) }
    }

    @objc public func hold(_ call: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.hold(call) }
    }

    @objc public func resume(_ call: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.resume(call) }
    }

    @objc public func transfer(_ call: String, target: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.transfer(call, to: target) }
    }

    @objc public func acceptTransfer(_ call: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.acceptTransfer(call) }
    }

    @objc public func rejectTransfer(_ call: String, code: Int, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.rejectTransfer(call, code: code) }
    }

    @objc public func sendDtmf(_ call: String, digits: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.sendDtmf(call, digits) }
    }

    @objc public func activateAudio(resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.activateAudio() }
    }

    @objc public func deactivateAudio(resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.deactivateAudio() }
    }

    @objc public func setMuted(_ muted: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.setMuted(muted) }
    }

    @objc public func setSystemEchoCancellation(_ on: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.setSystemEchoCancellation(on) }
    }

    @objc public func setDiagnosticTrace(_ on: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.setDiagnosticTrace(on) }
    }

    @objc public func networkTest(
        _ account: String, echoCall: String, echoMs: Double, timeoutMs: Double,
        resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) {
            try self.core.networkTest(account, echoCall: echoCall, echoMs: Int(echoMs), timeoutMs: Int(timeoutMs))
        }
    }

    @objc public func setCallGain(
        _ call: String, direction: String, gain: Double, resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) { try self.core.setCallGain(call, direction, gain) }
    }

    @objc public func setCallMuted(
        _ call: String, direction: String, muted: Bool, resolve: @escaping Resolve, reject: @escaping Reject
    ) {
        settle(resolve, reject) { try self.core.setCallMuted(call, direction, muted) }
    }

    @objc public func callAudio(_ call: String, direction: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.callAudio(call, direction) }
    }

    @objc public func setAppRate(_ call: String, hz: Int, resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.setAppRate(call, hz: hz) }
    }

    @objc public func settings(resolve: @escaping Resolve, reject: @escaping Reject) {
        settle(resolve, reject) { try self.core.settings() }
    }

    /// Close the stack when React Native tears the module down.
    @objc public func invalidate() {
        queue.async { self.core.close() }
    }

    private func settle(_ resolve: @escaping Resolve, _ reject: @escaping Reject, _ action: @escaping () throws -> Any) {
        queue.async {
            do {
                let result = try action()
                // a handle or an address as a string, a record as a
                // dictionary, and nothing for an action that returns none
                resolve((result as? String) ?? (result as? [String: Any]))
            } catch {
                let refused = SipralReactCore.refusal(of: error)
                reject(refused.code, refused.message, error)
            }
        }
    }
}
