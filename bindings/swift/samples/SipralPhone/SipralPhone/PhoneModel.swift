// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

@preconcurrency import AVFoundation
import CallKit
import Foundation
import Sipral
import UIKit

/// The phone: one stack, one account, one call at a time.
///
/// On a device, CallKit shows every call and PushKit wakes the application
/// for incoming ones (`docs/15-mobile.md`, "C2"); the iOS simulator refuses
/// both, so there the application rings and dials in its own screens. Every
/// call's audio is a `CallAudio` over `VoiceProcessingAudioDevice`, fed by
/// `AudioSessionObserver` and, with CallKit, by `CallKitBridge`.
@MainActor
final class PhoneModel: ObservableObject {
    enum Registration: Equatable {
        case off
        case registering
        case registered(since: Date)
        case failed(String)

        var text: String {
            switch self {
            case .off: return "Not registered"
            case .registering: return "Registering"
            case .registered(let since): return "Registered since \(EvidenceLog.timestamp(since))"
            case .failed(let why): return "Failed: \(why)"
            }
        }
    }

    @Published var settings: PhoneSettings
    @Published var password: String
    @Published private(set) var registration = Registration.off
    @Published private(set) var session: CallSession?
    @Published private(set) var offer: IncomingOffer?
    @Published private(set) var timeline: [String] = []
    @Published private(set) var networkText = "-"
    @Published private(set) var localAddress = "-"
    @Published private(set) var pushText = "-"
    @Published private(set) var lifecycleText = "-"
    @Published private(set) var countersText = "-"
    @Published var wholeMessages = true

    let log: EvidenceLog
    /// CallKit and PushKit: on a device, never on the simulator.
    let systemCalls: Bool

    private let store: SettingsStore
    private let script: LaunchScript
    private var callKit: CallKitAdapter?
    private var bridge: CallKitBridge?
    private var pushBridge: PushKitBridge?
    private var pushAdapter: PushKitAdapter?
    private let accountBox = AccountBox()
    private let lifecycle = SipralAppLifecycle(store: KeychainSnapshotStore(service: "org.sipral.phone.registration"))
    private var stack: SipralStack?
    private var account: Account?
    private var monitor: NetworkMonitor?
    private var eventTask: Task<Void, Never>?
    private var serverAddress = ""
    private var voipToken: [UInt8]?
    private var inBackground = false
    /// The account was added with push parameters, so the registrar's
    /// answer about them is worth reading.
    private var accountAskedForPush = false
    /// The stack's time to ready is said once: later registrations are
    /// refreshes, not the cold start it measures.
    private var readyNoted = false

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        log = EvidenceLog(directory: support.appendingPathComponent("Logs", isDirectory: true))
        store = SettingsStore(defaults: .standard, secrets: KeychainSecretStore(service: "org.sipral.phone"))
        script = LaunchScript(environment: ProcessInfo.processInfo.environment)
        #if targetEnvironment(simulator)
        systemCalls = false
        #else
        systemCalls = true
        #endif
        settings = script.settings ?? store.load()
        password = script.password ?? ((try? store.password()) ?? "")
        wholeMessages = settings.wholeMessages
        voipToken = store.voipToken
        log.onNote = { [weak self] line in
            Task { @MainActor in self?.appendTimeline(line) }
        }
    }

    private func appendTimeline(_ line: String) {
        timeline.append(line)
        if timeline.count > 300 { timeline.removeFirst(timeline.count - 300) }
    }

    private func note(_ text: String) {
        log.note(text)
    }

    // MARK: - launch

    /// From `application(_:didFinishLaunchingWithOptions:)`: PushKit has to
    /// be registered before that returns, so a launch a push caused gets
    /// the push.
    func launch() {
        let info = Bundle.main.infoDictionary
        note("launch \(info?["CFBundleShortVersionString"] ?? "?") (\(info?["CFBundleVersion"] ?? "?")), "
            + "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion), \(Self.machine()), "
            + "CallKit \(systemCalls ? "on" : "off (the simulator refuses it)")")
        lifecycle.storageFailed = { [log] error in
            log.note("registration snapshot not usable: \(error)")
        }
        if systemCalls {
            setUpSystemCalls()
        }
        if settings.isComplete {
            register()
        }
        script.run(on: self)
    }

    /// An account is up to place a call on.
    var canDial: Bool { stack != nil && account != nil }

    private func setUpSystemCalls() {
        let configuration = CXProviderConfiguration()
        configuration.supportsVideo = false
        configuration.maximumCallGroups = 1
        configuration.maximumCallsPerCallGroup = 1
        configuration.supportedHandleTypes = [.generic, .phoneNumber]
        configuration.includesCallsInRecents = true
        let adapter = CallKitAdapter(configuration: configuration)
        let bridge = CallKitBridge(provider: adapter)
        adapter.bridge = bridge
        let pushBridge = PushKitBridge(callKit: bridge)
        let box = accountBox
        let push = PushKitAdapter(bridge: pushBridge) { box.account }
        let log = self.log
        push.tokenChanged = { [weak self] token in
            Task { @MainActor in self?.tokenChanged(token) }
        }
        push.received = { pending in
            log.note("push received: \(pending.map { "call shown as \($0.uuid), caller \($0.callerId)" } ?? "nothing usable; shown and ended")")
        }
        callKit = adapter
        self.bridge = bridge
        self.pushBridge = pushBridge
        pushAdapter = push
        if let token = push.token {
            tokenChanged(token)
        }
        updatePushText()
    }

    private func tokenChanged(_ token: [UInt8]?) {
        let before = voipToken
        voipToken = token
        store.voipToken = token
        note(token == nil ? "VoIP push token invalidated" : "VoIP push token \(Self.hex(token ?? []))")
        updatePushText()
        // The token rides on every REGISTER: a new one means a new account.
        if token != before, account != nil {
            register()
        }
    }

    /// RFC 8599's parameters for the account, when there is a token and the
    /// build knows its team (`SipralTeamIdentifier`, from `DEVELOPMENT_TEAM`).
    var push: SipralPush? {
        guard let voipToken, let bundle = Bundle.main.bundleIdentifier, let team = Self.teamIdentifier else { return nil }
        return SipralPush.apnsVoip(token: voipToken, teamId: team, bundleId: bundle)
    }

    static var teamIdentifier: String? {
        guard let team = Bundle.main.object(forInfoDictionaryKey: "SipralTeamIdentifier") as? String,
              !team.isEmpty, !team.hasPrefix("$(") else { return nil }
        return team
    }

    private func updatePushText() {
        var parts: [String] = []
        if !systemCalls {
            parts.append("PushKit off (simulator)")
        } else if let voipToken {
            parts.append("token \(Self.hex(voipToken))")
        } else {
            parts.append("no token yet")
        }
        if systemCalls, Self.teamIdentifier == nil {
            parts.append("no team in this build: no pn-* sent")
        }
        if accountAskedForPush, let account, let echo = try? account.pushEcho() {
            parts.append(echo.accepted ? "registrar promised pushes" : "registrar promised nothing")
            if let lead = echo.refreshLeadMs { parts.append("refresh \(lead) ms ahead") }
        }
        pushText = parts.joined(separator: ", ")
    }

    // MARK: - the account

    /// Saves what the account screen holds and registers with it.
    func saveAndRegister() {
        settings.wholeMessages = wholeMessages
        do {
            try store.save(settings, password: password)
            note("account saved: \(settings.aor) via \(settings.server):\(settings.port) \(settings.transport.label)")
        } catch {
            note("account not saved: \(error)")
        }
        AVAudioSession.sharedInstance().requestRecordPermission { [log] granted in
            log.note("microphone \(granted ? "granted" : "refused")")
        }
        register()
    }

    /// A stack for the current settings, the account added and registered.
    /// Whatever ran before is unregistered and closed first; with nothing
    /// before it, as at launch, the account is up before this returns, so
    /// the push that may have caused the launch finds it.
    func register() {
        let settings = self.settings
        let password = self.password
        guard stack != nil else {
            open(settings, password: password)
            return
        }
        Task {
            await tearDown()
            open(settings, password: password)
        }
    }

    /// What the registration is written down under between processes: a
    /// changed account must not be handed the old one's binding.
    private var keptKey = ""

    private static func keptKey(_ settings: PhoneSettings) -> String {
        "\(settings.aor) \(settings.server):\(settings.port) \(settings.transport.rawValue)"
    }

    private func open(_ settings: PhoneSettings, password: String) {
        guard settings.isComplete else {
            registration = .failed("the account is incomplete")
            return
        }
        guard let ip = NetworkMonitor.resolve(settings.server) else {
            registration = .failed("\(settings.server) does not resolve")
            note("\(settings.server) does not resolve")
            return
        }
        serverAddress = "\(ip):\(settings.port)"
        let monitor = NetworkMonitor()
        let server = serverAddress
        let network = monitor.start(toward: server) { [weak self] network in
            Task { @MainActor in self?.networkChanged(network) }
        }
        self.monitor = monitor
        networkText = Self.describe(network)
        do {
            let transport: SipralTransport
            switch settings.transport {
            case .udp: transport = .udp
            case .tcp: transport = .tcp
            case .tls: transport = .tls
            }
            let stack = try SipralStack(
                audio: .application,
                userAgent: "SipralPhone/\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] ?? "0")",
                stunServer: settings.stunServer.isEmpty ? nil : settings.stunServer,
                network: network,
                signalling: transport,
                signallingServer: transport == .udp ? nil : server,
                tlsServerName: transport == .tls ? settings.server : nil,
                diagnosticTrace: wholeMessages
            )
            self.stack = stack
            try stack.setLog(level: .trace) { [log] level, target, message, suppressed in
                let text = suppressed == 0 ? message : "\(message) (\(suppressed) lines turned away before this one)"
                log.stack(level: "\(level)", target: target, message: text)
            }
            try lifecycle.launched(stack)
            readyNoted = false
            let events = stack.events()
            eventTask = Task { [weak self] in
                for await event in events {
                    self?.handle(event)
                }
            }
            let srtp: SipralSrtp
            switch settings.srtp {
            case .off: srtp = .notOffered
            case .offered: srtp = .offered
            case .required: srtp = .required
            }
            let account = try stack.addAccount(
                aor: settings.aor,
                registrarAddress: server,
                registrar: settings.registers ? settings.registrar : nil,
                displayName: settings.displayName.isEmpty ? nil : settings.displayName,
                authUser: password.isEmpty ? nil : settings.effectiveAuthUser,
                authPassword: password.isEmpty ? nil : password,
                security: AccountSecurity(srtp: srtp),
                push: push
            )
            self.account = account
            accountBox.account = account
            accountAskedForPush = push != nil
            localAddress = stack.bindAddress
            note("stack on \(stack.bindAddress) (\(settings.transport.label) to \(server)), account \(settings.aor)"
                + (push == nil ? ", no push parameters" : ", push parameters on the REGISTER"))
            keptKey = Self.keptKey(settings)
            if settings.registers {
                registration = .registering
                if lifecycle.restore(account, key: keptKey) {
                    // Believed on paper only: a REGISTER proves it now,
                    // continuing the binding the registrar already holds.
                    let state = (try? account.registrationState) ?? nil
                    note("registration restored from the keychain (\(state.map { "\($0)" } ?? "?")), refreshing it")
                    try account.refreshBinding()
                } else {
                    try account.register()
                }
            } else {
                registration = .off
                note("not registering: calls go straight to \(server)")
            }
            updatePushText()
        } catch {
            registration = .failed("\(error)")
            note("could not open the account: \(error)")
            eventTask?.cancel()
            eventTask = nil
            monitor.stop()
            self.monitor = nil
            accountBox.account = nil
            account = nil
            stack?.close()
            stack = nil
        }
    }

    /// Unregisters and closes, waiting up to two seconds for the
    /// registrar's answer so its challenge is not left unanswered.
    func unregister() {
        Task { await tearDown() }
    }

    /// The written-down registration goes too: the account is being
    /// unregistered or replaced, not suspended.
    private func tearDown() async {
        guard let stack else { return }
        if !keptKey.isEmpty {
            lifecycle.forget(key: keptKey)
            keptKey = ""
        }
        if let session {
            try? session.call.hangup()
            session.finish()
            self.session = nil
        }
        if let account, account.wantsRegistration {
            try? account.unregister()
            note("unregistering \(account.aor)")
            for _ in 0..<40 {
                if case .off = registration { break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
        }
        eventTask?.cancel()
        eventTask = nil
        monitor?.stop()
        monitor = nil
        accountBox.account = nil
        account = nil
        self.stack = nil
        stack.close()
        registration = .off
        note("stack closed")
    }

    // MARK: - events

    private func handle(_ event: SipralEvent) {
        note("event \(event.kindName)\(Self.detail(of: event))")
        switch event.kind {
        case .registrationChanged?:
            registrationChanged(event)
        case .callAnnounced?, .announcedCallMissing?:
            if let stack {
                pushBridge?.matchIncomingCall(event, on: stack)
            }
        case .incomingCall?:
            incoming(event)
        default:
            break
        }
    }

    private func registrationChanged(_ event: SipralEvent) {
        guard let state = event.registrationData?.state else { return }
        switch state {
        case .registered:
            if case .registered = registration {} else {
                registration = .registered(since: Date())
            }
            if !readyNoted, let account, let ready = try? account.timeToReadyMs() {
                readyNoted = true
                note("time to ready \(ready) ms from the stack's start")
            }
            updatePushText()
        case .registering, .refreshing, .retrying, .unverified, .restored:
            if case .registered = registration, state == .refreshing { return }
            registration = .registering
        case .failed:
            registration = .failed("status \(event.registrationData?.statusCode ?? 0)")
        case .unregistered, .idle, .notRegistering:
            registration = .off
        case .unknown:
            break
        }
    }

    // MARK: - calls

    /// Dials what the dial pad holds.
    func dial(_ typed: String) {
        guard let stack, let account, session == nil, !typed.isEmpty else { return }
        let target = settings.target(for: typed)
        note("dialling \(target)")
        let placedAt = Date()
        if let callKit {
            Task {
                do {
                    let (uuid, call) = try await callKit.startOutgoingCall(callee: target) {
                        try stack.placeCall(account: account, target: target)
                    }
                    attach(CallSession(call: call, uuid: uuid, remote: target, outgoing: true, placedAt: placedAt))
                } catch {
                    note("call not placed: \(error)")
                }
            }
        } else {
            do {
                let call = try stack.placeCall(account: account, target: target)
                attach(CallSession(call: call, uuid: nil, remote: target, outgoing: true, placedAt: placedAt))
            } catch {
                note("call not placed: \(error)")
            }
        }
    }

    private func incoming(_ event: SipralEvent) {
        guard let stack else { return }
        let caller = event.callData?.fromUri ?? "unknown"
        let pending = pushBridge?.matchIncomingCall(event, on: stack)
        guard session == nil else {
            note("busy: \(caller) refused with 486")
            try? stack.rejectCall(event, code: 486)
            return
        }
        guard let bridge else {
            offer = IncomingOffer(event: event, caller: caller)
            if script.answers {
                answer()
            }
            return
        }
        do {
            let call = try stack.takeIncomingCall(event)
            if let pending {
                // The session takes its events first: an Answer tapped on
                // the push's screen is carried out the moment the call is
                // bound, and its confirmation must be seen.
                attach(CallSession(call: call, uuid: pending.uuid, remote: caller, outgoing: false))
                note("the INVITE matched the push shown as \(pending.uuid)")
                pending.resolve(with: call)
            } else {
                Task {
                    do {
                        let uuid = try await bridge.reportIncomingCall(callerId: caller)
                        bridge.bind(uuid: uuid, to: call)
                        attach(CallSession(call: call, uuid: uuid, remote: caller, outgoing: false))
                    } catch {
                        note("CallKit refused the call: \(error)")
                        try? call.reject(code: 486)
                        call.close()
                    }
                }
            }
        } catch {
            note("incoming call lost: \(error)")
        }
    }

    /// The application's own Answer, where CallKit does not show the call.
    func answer() {
        guard let stack, let offer else { return }
        self.offer = nil
        do {
            let call = try stack.takeIncomingCall(offer.event)
            attach(CallSession(call: call, uuid: nil, remote: offer.caller, outgoing: false))
            try call.answer()
        } catch {
            note("answer failed: \(error)")
        }
    }

    func decline() {
        guard let stack, let offer else { return }
        self.offer = nil
        try? stack.rejectCall(offer.event, code: 603)
    }

    private func attach(_ session: CallSession) {
        self.session = session
        let call = session.call
        let events = call.events()
        session.tasks.append(Task { [weak self, weak session] in
            for await event in events {
                guard let self, let session else { return }
                self.callEvent(event, session: session)
            }
        })
        session.tasks.append(Task { [weak self, weak session] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self, let session else { return }
                self.sample(session)
            }
        })
        note("call \(session.outgoing ? "to" : "from") \(session.remote)\(session.uuid.map { ", CallKit \($0)" } ?? "")")
        if session.outgoing, let digits = script.digits {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                self?.sendDigits(digits)
            }
        }
        if let seconds = script.callSeconds {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
                self?.hangUp()
            }
        }
    }

    private func callEvent(_ event: SipralEvent, session: CallSession) {
        // a closed call's handle names nothing any more
        guard self.session === session else { return }
        if event.kind != .callEnded, let state = try? session.call.state {
            session.state = "\(state)"
        }
        switch event.kind {
        case .callConfirmed?:
            if session.confirmedAt == nil {
                let now = Date()
                session.confirmedAt = now
                note(String(format: "call confirmed %.0f ms after it was %@", now.timeIntervalSince(session.placedAt) * 1000,
                            session.outgoing ? "placed" : "taken"))
            }
        case .mediaStarted?:
            startAudio(session)
        case .callAddressWanted?:
            do {
                try session.call.moveMedia()
                note("media offered at the new address")
            } catch {
                note("the call could not move: \(error)")
            }
        case .callEnded?:
            ended(session, event: event)
        default:
            break
        }
        if let data = event.callData {
            session.held = data.heldHere
        }
    }

    private func startAudio(_ session: CallSession) {
        guard session.audio == nil, let media = session.call.media else { return }
        let audio = CallAudio(media: media, device: VoiceProcessingAudioDevice(managesSession: bridge == nil))
        session.audio = audio
        audio.follow(session.call)
        if let bridge, let uuid = session.uuid {
            bridge.attach(audio, to: uuid)
        }
        session.observer = AudioSessionObserver(audio: audio)
        let transitions = audio.transitions()
        session.tasks.append(Task { [weak self, weak session] in
            for await transition in transitions {
                guard let self, let session else { return }
                self.note("audio \(transition)")
                session.audioState = "\(audio.state)"
                if case .routeChanged(let route) = transition {
                    session.route = "\(route.output) (\(route.outputType))"
                }
                if case .muteChanged(let muted) = transition {
                    session.muted = muted
                }
            }
        })
        audio.start()
        let output = AVAudioSession.sharedInstance().currentRoute.outputs.first
        session.route = output.map { "\($0.portName) (\($0.portType.rawValue))" } ?? ""
        note("audio started at \(media.sampleRate) Hz, route \(session.route)")
    }

    private func sample(_ session: CallSession) {
        guard let media = session.call.media, let stats = try? media.statistics() else { return }
        let text = "sent \(stats.packets_sent), received \(stats.packets_received), lost \(stats.packets_lost)"
        session.statistics = text
        note("media \(text)")
    }

    private func ended(_ session: CallSession, event: SipralEvent) {
        let cause = event.callData?.endCause.map { $0.text ?? "SIP \($0.sip ?? 0)" } ?? "\(event.callData?.endReason.map { "\($0)" } ?? "?")"
        if let stats = session.call.finalStatistics {
            note("call ended (\(cause)): sent \(stats.packets_sent), received \(stats.packets_received), lost \(stats.packets_lost)")
        } else {
            note("call ended (\(cause))")
        }
        session.finish()
        session.call.close()
        if self.session === session {
            self.session = nil
        }
        script.callEnded(on: self)
    }

    // MARK: - in a call

    func hangUp() {
        guard let session else { return }
        if let callKit, let uuid = session.uuid {
            request(CXEndCallAction(call: uuid), via: callKit)
        } else {
            try? session.call.hangup()
        }
    }

    func setMuted(_ muted: Bool) {
        guard let session else { return }
        if let callKit, let uuid = session.uuid {
            request(CXSetMutedCallAction(call: uuid, muted: muted), via: callKit)
        } else {
            session.audio?.setMuted(muted)
            session.muted = muted
        }
    }

    func setHeld(_ held: Bool) {
        guard let session else { return }
        if let callKit, let uuid = session.uuid {
            request(CXSetHeldCallAction(call: uuid, onHold: held), via: callKit)
            return
        }
        do {
            if held {
                session.audio?.pause(.held)
                try session.call.hold()
            } else {
                session.audio?.resume(.held)
                try session.call.resume()
            }
            session.held = held
        } catch {
            note("hold failed: \(error)")
        }
    }

    func sendDigits(_ digits: String) {
        guard let session else { return }
        session.digits += digits
        note("digits \(digits)")
        if let callKit, let uuid = session.uuid {
            request(CXPlayDTMFCallAction(call: uuid, digits: digits, type: .singleTone), via: callKit)
        } else {
            try? session.call.sendDtmf(digits)
        }
    }

    func setSpeaker(_ on: Bool) {
        do {
            try AVAudioSession.sharedInstance().overrideOutputAudioPort(on ? .speaker : .none)
            session?.speaker = on
        } catch {
            note("speaker override failed: \(error)")
        }
    }

    private func request(_ action: CXCallAction, via callKit: CallKitAdapter) {
        Task {
            do {
                try await callKit.request(action)
            } catch {
                note("CallKit refused \(type(of: action)): \(error)")
            }
        }
    }

    // MARK: - the network and the process

    private func networkChanged(_ network: SipralStack.Network) {
        networkText = Self.describe(network)
        guard let stack else { return }
        do {
            let recovery = try stack.networkChanged(to: network)
            localAddress = stack.bindAddress
            note("network changed to \(networkText): \(recovery)")
        } catch {
            note("network change to \(networkText) failed: \(error)")
        }
    }

    /// The scene moved. Into the background with no call, the registration
    /// is written into the keychain and the stack told it is suspending (a
    /// process iOS will freeze, and may end); back, that it resumed
    /// (`SipralAppLifecycle`).
    func scene(active: Bool) {
        if !active {
            guard !inBackground else { return }
            inBackground = true
            guard stack != nil else {
                note("background")
                return
            }
            if let report = lifecycle.enteredBackground() {
                note("background: registration written down, suspending: \(report.unverified) bindings no longer believed, \(report.calls) calls")
                lifecycleText = "suspended at \(EvidenceLog.timestamp(Date()))"
            } else {
                note("background with a call up: not suspending")
                lifecycleText = "background, call up"
            }
        } else {
            guard inBackground else { return }
            inBackground = false
            guard stack != nil else {
                note("foreground")
                return
            }
            lifecycle.enteredForeground()
            note("foreground: resumed")
            lifecycleText = "resumed at \(EvidenceLog.timestamp(Date()))"
        }
    }

    // MARK: - diagnostics

    func setWholeMessages(_ on: Bool) {
        wholeMessages = on
        settings.wholeMessages = on
        try? stack?.setDiagnosticTrace(on)
        note("whole SIP messages in the log \(on ? "on" : "off")")
    }

    func refreshDiagnostics() {
        guard let stack else {
            countersText = "-"
            return
        }
        localAddress = stack.bindAddress
        updatePushText()
        if let counters = try? stack.counters() {
            countersText = Mirror(reflecting: counters).children
                .compactMap { child in child.label.map { "\($0) \(child.value)" } }
                .joined(separator: "\n")
        }
    }

    /// The evidence file, written into the caches, for the share sheet.
    func writeEvidence() -> URL? {
        refreshDiagnostics()
        log.flush()
        let info = Bundle.main.infoDictionary
        let abi = try? Sipral.abiVersion()
        var about: [(String, String)] = [
            ("written", EvidenceLog.timestamp(Date())),
            ("application", "\(Bundle.main.bundleIdentifier ?? "?") \(info?["CFBundleShortVersionString"] ?? "?") (\(info?["CFBundleVersion"] ?? "?"))"),
            ("Sipral C ABI", abi.map { "\($0.major).\($0.minor).\($0.patch)" } ?? "?"),
            ("device", "\(Self.machine()), \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"),
            ("CallKit and PushKit", systemCalls ? "on" : "off (simulator)"),
            ("account", "\(settings.aor), server \(settings.server):\(settings.port) (\(serverAddress)) over \(settings.transport.label)"),
            ("auth user", settings.effectiveAuthUser),
            ("srtp", settings.srtp.rawValue),
            ("stun", settings.stunServer.isEmpty ? "none" : settings.stunServer),
            ("whole SIP messages", wholeMessages ? "on" : "off"),
            ("registration", registration.text),
            ("local address", localAddress),
            ("network", networkText),
            ("push", pushText),
            ("lifecycle", lifecycleText),
            ("battery", Self.battery()),
        ]
        if let session {
            about.append(("call", "\(session.remote), \(session.state), \(session.statistics)"))
        }
        about.append(("counters", countersText.replacingOccurrences(of: "\n", with: ", ")))
        do {
            let url = try EvidenceBundle.write(
                into: FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("Evidence", isDirectory: true),
                about: about,
                logFiles: log.files,
                decisions: try? stack?.diagnosticsJson(),
                state: try? stack?.state(),
                secrets: [password, script.password ?? ""]
            )
            note("evidence written: \(url.lastPathComponent)")
            return url
        } catch {
            note("evidence not written: \(error)")
            return nil
        }
    }

    // MARK: - helpers

    static func describe(_ network: SipralStack.Network) -> String {
        "\(network.link) \(network.address ?? "no address") on \(network.interface ?? "-")"
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func machine() -> String {
        var name = utsname()
        uname(&name)
        return withUnsafeBytes(of: &name.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    static func battery() -> String {
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        let state: String
        switch UIDevice.current.batteryState {
        case .charging: state = "charging"
        case .full: state = "full"
        case .unplugged: state = "unplugged"
        default: state = "unknown"
        }
        return level < 0 ? "unknown" : String(format: "%.0f%% (%@)", level * 100, state)
    }

    static func detail(of event: SipralEvent) -> String {
        if let registration = event.registrationData {
            return ": \(registration.state.map { "\($0)" } ?? "?") status \(registration.statusCode)"
        }
        if let call = event.callData, event.kind == .incomingCall || event.kind == .callEnded {
            let reason = event.kind == .callEnded ? call.endReason.map { " \($0)" } ?? "" : ""
            return ": \(call.fromUri ?? "?")\(reason)"
        }
        if let announce = event.announceData {
            return ": announcement \(announce.announcement), waited \(announce.waitedMs) ms"
        }
        return ""
    }
}
