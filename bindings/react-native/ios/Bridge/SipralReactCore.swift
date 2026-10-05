// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Everything the React Native module does on iOS, with nothing of React
// Native in it: one SipralStack from bindings/swift, its accounts and calls
// kept by the handle JavaScript names them with, and every event flattened
// into the dictionary the codegen spec's NativeEvent describes. The
// Objective-C++ module is the few lines that hand this to the bridge;
// scripts/check.sh builds this with the Swift layer and tests it on macOS,
// over real stacks, without any of React Native.

import Foundation
import Sipral

/// A refusal JavaScript receives as `SipralError.code`: a status's name, or
/// one of this layer's.
public struct SipralRefusal: Error, Equatable {
    public let code: String
    public let message: String

    public init(_ code: String, _ message: String) {
        self.code = code
        self.message = message
    }
}

/// What `open` takes, the fields of the spec's NativeOpenOptions.
public struct SipralOpenOptions {
    /// Nil for the route toward the server, the Swift layer's default.
    public var bindHost: String?
    public var bindPort: UInt16 = 0
    public var userAgent: String?
    public var codecs: String?
    public var signalling = "udp"
    public var signallingServer: String?
    public var stunServer: String?
    public var manualAudio = false
    /// A `SipralSrtp` case's name: "offered", "bestEffort"...
    public var srtp: String?
    /// Suite names, comma-separated.
    public var srtpSuites: String?
    public var pathMtu: UInt32 = 0
    public var datagramWithoutStreamBytes: UInt32 = 0
    /// The pseudonym salt, as hexadecimal.
    public var pseudonymSalt: String?
    public var diagnosticTrace: Bool?
    /// The fingerprint of the one certificate a TLS connection trusts.
    public var tlsPin: String?
    /// False opens the devices past the platform's echo cancellation.
    public var systemEchoCancellation: Bool?
    /// What a party this end holds is sent: "silence" or "application";
    /// nil for silence.
    public var heldAudio: String?
    /// The most calls held at once, 0 for 128.
    public var maxDialogs: UInt32 = 0
    /// The most requests from other ends worked on at once, 0 for 256.
    public var maxServerTransactions: UInt32 = 0

    public init(bindHost: String? = nil) {
        self.bindHost = bindHost
    }

    /// Read out of what JavaScript handed over; a member left out is the default.
    public init(_ options: [String: Any]) {
        bindHost = (options["bindHost"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        bindPort = UInt16(clamping: (options["bindPort"] as? NSNumber)?.intValue ?? 0)
        userAgent = options["userAgent"] as? String
        codecs = options["codecs"] as? String
        signalling = options["signalling"] as? String ?? "udp"
        signallingServer = options["signallingServer"] as? String
        stunServer = options["stunServer"] as? String
        manualAudio = (options["manualAudio"] as? NSNumber)?.boolValue ?? false
        srtp = options["srtp"] as? String
        srtpSuites = options["srtpSuites"] as? String
        pathMtu = UInt32(clamping: (options["pathMtu"] as? NSNumber)?.intValue ?? 0)
        datagramWithoutStreamBytes = UInt32(clamping: (options["datagramWithoutStreamBytes"] as? NSNumber)?.intValue ?? 0)
        pseudonymSalt = options["pseudonymSalt"] as? String
        diagnosticTrace = (options["diagnosticTrace"] as? NSNumber)?.boolValue
        tlsPin = options["tlsPin"] as? String
        systemEchoCancellation = (options["systemEchoCancellation"] as? NSNumber)?.boolValue
        heldAudio = options["heldAudio"] as? String
        maxDialogs = UInt32(clamping: (options["maxDialogs"] as? NSNumber)?.int64Value ?? 0)
        maxServerTransactions = UInt32(clamping: (options["maxServerTransactions"] as? NSNumber)?.int64Value ?? 0)
    }
}

/// What `addAccount` takes, the fields of NativeAccountOptions.
public struct SipralAccountOptions {
    public var aor: String
    /// Nil for an account whose server is `serverUri`.
    public var registrarAddress: String?
    public var serverUri: String?
    public var serverNaptr = false
    public var keepaliveMs: UInt64 = 0
    public var registrar: String?
    public var contact: String?
    public var displayName: String?
    public var authUser: String?
    public var authPassword: String?
    public var expiresSeconds: UInt64 = 0
    /// "tcp" or "tls": a connection of the account's own to its server.
    public var streamProtocol: String?
    /// The fingerprint, as bare hexadecimal, of the one certificate that
    /// connection trusts.
    public var tlsPin: String?
    /// The realms the password answers, one per line.
    public var realms: String?

    public init(aor: String, registrarAddress: String? = nil, serverUri: String? = nil) {
        self.aor = aor
        self.registrarAddress = registrarAddress
        self.serverUri = serverUri
    }

    public init(_ options: [String: Any]) {
        aor = options["aor"] as? String ?? ""
        registrarAddress = options["registrarAddress"] as? String
        serverUri = options["serverUri"] as? String
        serverNaptr = (options["serverNaptr"] as? NSNumber)?.boolValue ?? false
        keepaliveMs = UInt64(max(0, (options["keepaliveMs"] as? NSNumber)?.doubleValue ?? 0))
        registrar = options["registrar"] as? String
        contact = options["contact"] as? String
        displayName = options["displayName"] as? String
        authUser = options["authUser"] as? String
        authPassword = options["authPassword"] as? String
        expiresSeconds = UInt64(max(0, (options["expiresSeconds"] as? NSNumber)?.doubleValue ?? 0))
        streamProtocol = options["streamProtocol"] as? String
        tlsPin = options["tlsPin"] as? String
        realms = options["realms"] as? String
    }
}

/// One stack and what hangs off it. `emit` is called with each event,
/// flattened, on the task that reads the stack's events.
///
/// `audio` decides who runs the calls' audio: `deviceAudio` on a phone,
/// `.application` in a test that has no devices.
public final class SipralReactCore: @unchecked Sendable {
    private let emit: @Sendable ([String: Any]) -> Void
    private let audio: (Bool) throws -> AudioMode
    private let lock = NSRecursiveLock()
    private var stack: SipralStack?
    private var reader: Task<Void, Never>?
    /// Where every call's media is bound: what JavaScript named, or nil for
    /// the route toward the far end the Swift layer picks.
    private var mediaHost: String?
    private var accounts: [String: Account] = [:]
    private var calls: [String: Call] = [:]
    private var arrived: [String: SipralEvent] = [:]
    private var transfers: [String: SipralEvent] = [:]

    public init(
        emit: @escaping @Sendable ([String: Any]) -> Void,
        audio: @escaping (Bool) throws -> AudioMode = SipralReactCore.deviceAudio
    ) {
        self.emit = emit
        self.audio = audio
    }

    /// Open the stack; the address it signals from comes back.
    public func open(_ options: SipralOpenOptions) throws -> String {
        try guarded {
            try locked {
                if stack != nil {
                    throw SipralRefusal("wrongState", "a client is already open; close it first")
                }
                let signalling: SipralTransport
                switch options.signalling {
                case "udp": signalling = .udp
                case "tcp": signalling = .tcp
                case "tls": signalling = .tls
                default: throw SipralRefusal("invalidArgument", "signalling is udp, tcp or tls, not \(options.signalling)")
                }
                var srtp: SipralSrtp?
                if let named = options.srtp {
                    guard let found = Self.srtpCases.first(where: { String(describing: $0) == named }) else {
                        throw SipralRefusal("invalidArgument", "srtp is no SRTP policy: \(named)")
                    }
                    srtp = found
                }
                var trust = TLSTrust.platform
                if let pin = options.tlsPin {
                    trust = try TLSTrust.pinned(pin)
                }
                let heldAudio: SipralHeldAudio
                switch options.heldAudio {
                case nil: heldAudio = .default
                case "silence": heldAudio = .silence
                case "application": heldAudio = .application
                case let other?: throw SipralRefusal("invalidArgument", "heldAudio is silence or application, not \(other)")
                }
                let opened = try SipralStack(
                    audio: try audio(options.manualAudio),
                    bindHost: options.bindHost,
                    bindPort: options.bindPort,
                    userAgent: options.userAgent,
                    codecs: options.codecs,
                    srtp: srtp,
                    stunServer: options.stunServer,
                    maxDialogs: options.maxDialogs,
                    maxServerTransactions: options.maxServerTransactions,
                    signalling: signalling,
                    signallingServer: options.signallingServer,
                    tlsTrust: trust,
                    srtpSuites: options.srtpSuites.map { $0.split(separator: ",").map(String.init) } ?? [],
                    pathMtu: options.pathMtu,
                    datagramWithoutStreamBytes: options.datagramWithoutStreamBytes,
                    pseudonymSalt: try options.pseudonymSalt.map(Self.bytes(hex:)),
                    diagnosticTrace: options.diagnosticTrace,
                    systemEchoCancellation: options.systemEchoCancellation,
                    heldAudio: heldAudio
                )
                let events = opened.events()
                reader = Task { [weak self] in
                    for await event in events {
                        self?.deliver(event)
                    }
                }
                stack = opened
                mediaHost = options.bindHost
                return opened.bindAddress
            }
        }
    }

    public func close() {
        let closing: SipralStack? = locked {
            let was = stack
            stack = nil
            reader?.cancel()
            reader = nil
            calls.values.forEach { $0.close() }
            calls.removeAll()
            accounts.removeAll()
            arrived.removeAll()
            transfers.removeAll()
            return was
        }
        closing?.close()
    }

    public func addAccount(_ options: SipralAccountOptions) throws -> String {
        try guarded {
            var stream: SipralTransport?
            switch options.streamProtocol {
            case nil: stream = nil
            case "tcp": stream = .tcp
            case "tls": stream = .tls
            case let other?: throw SipralRefusal("invalidArgument", "streamProtocol is tcp or tls, not \(other)")
            }
            let account = try open().addAccount(
                aor: options.aor,
                registrarAddress: options.registrarAddress,
                serverUri: options.serverUri,
                serverNaptr: options.serverNaptr,
                keepaliveMs: options.keepaliveMs,
                tlsPin: options.tlsPin,
                streamProtocol: stream,
                registrar: options.registrar,
                contact: options.contact,
                displayName: options.displayName,
                authUser: options.authUser,
                authPassword: options.authPassword,
                expiresSeconds: options.expiresSeconds,
                realms: options.realms.map { $0.split(separator: "\n").map(String.init) } ?? []
            )
            let id = String(account.handle)
            locked { accounts[id] = account }
            return id
        }
    }

    public func register(_ account: String) throws {
        try guarded { try accountOf(account).register() }
    }

    public func unregister(_ account: String) throws {
        try guarded { try accountOf(account).unregister() }
    }

    public func removeAccount(_ account: String) throws {
        try guarded {
            try accountOf(account).remove()
            _ = locked { accounts.removeValue(forKey: account) }
        }
    }

    public func placeCall(_ account: String, _ target: String, destination: String?, codecs: String?) throws -> String {
        try guarded {
            keep(try open().placeCall(
                account: try accountOf(account), target: target, mediaHost: mediaHost,
                destination: destination, codecs: codecs
            ))
        }
    }

    public func answer(_ call: String) throws {
        try guarded {
            let event = try take(call, from: \.arrived, "call \(call) is not waiting to be answered")
            do {
                _ = keep(try open().answerCall(event, mediaHost: mediaHost))
            } catch {
                locked { arrived[call] = event }
                throw error
            }
        }
    }

    public func reject(_ call: String, code: Int) throws {
        try guarded {
            let event = try take(call, from: \.arrived, "call \(call) is not waiting to be answered")
            do {
                try open().rejectCall(event, code: UInt32(clamping: code))
            } catch {
                locked { arrived[call] = event }
                throw error
            }
        }
    }

    /// A call answered or placed is hung up; one still ringing here is turned away, 486.
    public func hangup(_ call: String) throws {
        try guarded {
            if let kept = locked({ calls[call] }) {
                try kept.hangup()
            } else if let event = locked({ arrived.removeValue(forKey: call) }) {
                try open().rejectCall(event)
            } else {
                throw SipralRefusal("invalidHandle", "no call \(call)")
            }
        }
    }

    public func hold(_ call: String) throws {
        try guarded { try callOf(call).hold() }
    }

    public func resume(_ call: String) throws {
        try guarded { try callOf(call).resume() }
    }

    public func transfer(_ call: String, to target: String) throws {
        try guarded { try callOf(call).transfer(to: target) }
    }

    /// Take the transfer the far end of `call` asked for; the call placed to
    /// its target comes back.
    public func acceptTransfer(_ call: String) throws -> String {
        try guarded {
            let event = try take(call, from: \.transfers, "the far end of call \(call) asked for no transfer")
            do {
                return keep(try open().acceptReferral(event, mediaHost: mediaHost))
            } catch {
                locked { transfers[call] = event }
                throw error
            }
        }
    }

    public func rejectTransfer(_ call: String, code: Int) throws {
        try guarded {
            let event = try take(call, from: \.transfers, "the far end of call \(call) asked for no transfer")
            try open().rejectReferral(event, code: UInt32(clamping: code))
        }
    }

    public func sendDtmf(_ call: String, _ digits: String) throws {
        try guarded { try callOf(call).sendDtmf(digits) }
    }

    public func activateAudio() throws {
        try guarded { try devices().activate() }
    }

    public func deactivateAudio() throws {
        try guarded { try devices().deactivate() }
    }

    public func setMuted(_ muted: Bool) throws {
        try guarded { try devices().setMuted(muted, for: .input) }
    }

    public func setDiagnosticTrace(_ on: Bool) throws {
        try guarded { try open().setDiagnosticTrace(on) }
    }

    /// One call's own gain in one direction, "input" or "output".
    public func setCallGain(_ call: String, _ direction: String, _ gain: Double) throws {
        try guarded { try devices().setGain(gain, for: try Self.direction(direction), of: try callOf(call)) }
    }

    public func setCallMuted(_ call: String, _ direction: String, _ muted: Bool) throws {
        try guarded { try devices().setMuted(muted, for: try Self.direction(direction), of: try callOf(call)) }
    }

    /// One call's own gain, mute and meter in one direction, as the spec's
    /// NativeCallAudio.
    public func callAudio(_ call: String, _ direction: String) throws -> [String: Any] {
        try guarded {
            let audio = try devices()
            let kept = try callOf(call)
            let way = try Self.direction(direction)
            return [
                "gain": try audio.gain(for: way, of: kept),
                "muted": try audio.isMuted(way, of: kept),
                "level": try audio.level(for: way, of: kept),
            ]
        }
    }

    /// `sipral_media_set_app_rate` on the call's media, and the rate and
    /// frame length it came to, as the spec's NativeAppRate. A call with no
    /// audio yet is `wrongState`, and so is one on the phone's own devices,
    /// which the library refuses.
    public func setAppRate(_ call: String, hz: Int) throws -> [String: Any] {
        try guarded {
            guard let media = try callOf(call).media else {
                throw SipralRefusal("wrongState", "call \(call) has no audio yet")
            }
            guard let rate = UInt32(exactly: hz) else {
                throw SipralRefusal("invalidArgument", "an application rate is 8000, 16000, 24000 or 48000, or 0")
            }
            try media.setAppRate(rate)
            return ["sampleRate": media.sampleRate, "frameSamples": media.frameSamples]
        }
    }

    /// What the stack runs with, as the spec's NativeSettings.
    public func settings() throws -> [String: Any] {
        try guarded {
            let read = try open().settings()
            let transport: String
            switch read.transport {
            case .tcp?: transport = "tcp"
            case .tls?: transport = "tls"
            default: transport = "udp"
            }
            return [
                "transport": transport,
                "codecCount": read.codecCount,
                "frameMs": Int(read.frameMs),
                "srtpSuites": read.srtpSuites.map { String($0.rawValue) }.joined(separator: ","),
                "pseudonymSalted": read.pseudonymSalted,
                "diagnosticTrace": read.diagnosticTrace,
                "systemEchoCancellation": read.systemEchoCancellation,
            ]
        }
    }

    /// A direction by the name JavaScript gives it.
    static func direction(_ named: String) throws -> SipralAudioDirection {
        switch named {
        case "input": return .input
        case "output": return .output
        default: throw SipralRefusal("invalidArgument", "a direction is input or output, not \(named)")
        }
    }

    /// Every SRTP policy, by the name JavaScript gives it.
    private static let srtpCases: [SipralSrtp] = [
        .notOffered, .offered, .required, .dtls, .dtlsRequired, .dtlsOrSdes, .bestEffort,
    ]

    /// The bytes [hex] writes, two digits each.
    static func bytes(hex: String) throws -> [UInt8] {
        let digits = Array(hex)
        guard digits.count % 2 == 0 else {
            throw SipralRefusal("invalidArgument", "pseudonymSalt is bytes as hexadecimal")
        }
        return try stride(from: 0, to: digits.count, by: 2).map { at in
            guard let byte = UInt8(String(digits[at...at + 1]), radix: 16) else {
                throw SipralRefusal("invalidArgument", "pseudonymSalt is bytes as hexadecimal")
            }
            return byte
        }
    }

    private func deliver(_ event: SipralEvent) {
        let id = String(event.call)
        locked {
            if event.kind == .incomingCall {
                arrived[id] = event
            } else if event.kind == .transferRequested {
                transfers[id] = event
            }
        }
        emit(Self.flatten(event))
        if event.kind == .callEnded {
            let ended: Call? = locked {
                arrived.removeValue(forKey: id)
                transfers.removeValue(forKey: id)
                return calls.removeValue(forKey: id)
            }
            ended?.close()
        }
    }

    private func keep(_ call: Call) -> String {
        let id = String(call.handle)
        locked { calls[id] = call }
        return id
    }

    private func take(
        _ id: String, from table: ReferenceWritableKeyPath<SipralReactCore, [String: SipralEvent]>, _ why: String
    ) throws -> SipralEvent {
        guard let event = locked({ self[keyPath: table].removeValue(forKey: id) }) else {
            throw SipralRefusal("wrongState", why)
        }
        return event
    }

    private func open() throws -> SipralStack {
        guard let stack = locked({ stack }) else { throw SipralRefusal("closed", "the client is not open") }
        return stack
    }

    private func accountOf(_ id: String) throws -> Account {
        guard let account = locked({ accounts[id] }) else { throw SipralRefusal("invalidHandle", "no account \(id)") }
        return account
    }

    private func callOf(_ id: String) throws -> Call {
        guard let call = locked({ calls[id] }) else {
            throw SipralRefusal("invalidHandle", "no call \(id) answered or placed")
        }
        return call
    }

    private func devices() throws -> AudioDevices {
        guard let devices = try open().audio else {
            throw SipralRefusal("notSupported", "the library runs no audio devices on this client")
        }
        return devices
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// Device mode wherever the library has an engine for the platform, and
    /// a refusal where it has none: nothing in JavaScript could carry a
    /// call's audio there.
    public static func deviceAudio(manual: Bool) throws -> AudioMode {
        guard AudioMode.platformDefault.isDevice else {
            throw SipralRefusal("notSupported", "this build of the library runs no audio devices here")
        }
        return .device(activation: manual ? .manual : .automatic)
    }

    /// What `failure` reaches JavaScript as: a status by its name, anything
    /// else as the platform's.
    public static func refusal(of failure: Error) -> SipralRefusal {
        switch failure {
        case let refused as SipralRefusal:
            return refused
        case let failed as SipralError:
            return SipralRefusal(failed.status.map { String(describing: $0) } ?? "platform", failed.message)
        default:
            return SipralRefusal("platform", String(describing: failure))
        }
    }

    private func guarded<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch {
            throw Self.refusal(of: error)
        }
    }

    /// One event as the spec's NativeEvent: the members its kind does not
    /// use are left out.
    public static func flatten(_ event: SipralEvent) -> [String: Any] {
        var flat: [String: Any] = [
            "kind": event.kind.map { String(describing: $0) } ?? "unknown",
            "kindName": event.kindName,
            "account": event.account == Sipral.handleNone ? "" : String(event.account),
            "call": event.call == Sipral.handleNone ? "" : String(event.call),
        ]
        if let registration = event.registrationData {
            if let state = registration.state {
                flat["registrationState"] = String(describing: state)
            }
            if let failure = SipralRegistrationFailure(rawValue: registration.failure), failure != .none {
                flat["registrationFailure"] = String(describing: failure)
            }
            flat["statusCode"] = Int(registration.statusCode)
            flat["retryInMs"] = Double(registration.retryInMs)
        } else if let call = event.callData {
            if let state = call.state {
                flat["callState"] = String(describing: state)
            }
            if let reason = call.endReason {
                flat["endReason"] = String(describing: reason)
            }
            flat["statusCode"] = Int(call.statusCode)
            flat["retryInMs"] = Double(call.retryInMs)
            flat["heldHere"] = call.heldHere
            flat["heldThere"] = call.heldThere
            call.fromUri.map { flat["fromUri"] = $0 }
            call.fromDisplay.map { flat["fromDisplay"] = $0 }
            call.toUri.map { flat["toUri"] = $0 }
        } else if let transfer = event.transferData {
            flat["statusCode"] = Int(transfer.statusCode)
            flat["attended"] = transfer.attended
            transfer.target.map { flat["target"] = $0 }
        } else if event.kind == .digitReceived || event.kind == .inBandDigit, let digit = event.mediaData?.digit {
            flat["digit"] = String(digit)
        } else if let challenge = event.challengeData {
            challenge.refusal.map { flat["challengeRefusal"] = String(describing: $0) }
            challenge.server.map { flat["challengeServer"] = $0 }
            flat["challengeRealms"] = challenge.realms.joined(separator: "\n")
        } else if let locate = event.locateData {
            locate.targets.map { flat["targets"] = $0 }
            if event.kind == .locateFailed, let failure = SipralLocateFailure(rawValue: locate.failureRaw) {
                flat["locateFailure"] = String(describing: failure)
                flat["retryInMs"] = Double(locate.retryInMs)
            }
        }
        return flat
    }
}
