// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import SwiftUI
import Sipral

/// A skeleton, not a product: registration, a call, hold, DTMF, devices --
/// in one window.
struct ContentView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Account") {
                VStack(alignment: .leading) {
                    LabeledContent("AOR") { TextField("sip:alice@example.invalid", text: $model.aor) }
                    LabeledContent("Registrar address") { TextField("host:port", text: $model.registrarAddress) }
                    LabeledContent("Registrar") { TextField("sip:example.invalid (optional)", text: $model.registrar) }
                    LabeledContent("Auth user") { TextField("optional", text: $model.authUser) }
                    LabeledContent("Auth password") { SecureField("optional", text: $model.authPassword) }
                    HStack {
                        Button("Register") { model.register() }
                        Text(statusText)
                    }
                }
            }

            GroupBox("Call") {
                VStack(alignment: .leading) {
                    LabeledContent("Target") { TextField("sip:bob@host:port", text: $model.target) }
                    HStack {
                        Button("Call") { model.placeCall() }
                        Button("Hang up") { model.hangup() }
                        Button(model.onHold ? "Resume" : "Hold") { model.toggleHold() }
                    }
                    if let state = model.callState {
                        Text("state: \(String(describing: state))")
                    }
                    if let incoming = model.incoming {
                        HStack {
                            VStack(alignment: .leading) {
                                Text("\(incoming.caller) is calling").bold()
                                if !incoming.detail.isEmpty {
                                    Text(incoming.detail).font(.footnote)
                                }
                            }
                            Button("Answer") { model.answer() }
                            Button("Decline") { model.decline() }
                        }
                    }
                }
            }

            GroupBox("DTMF") {
                HStack {
                    ForEach(["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"], id: \.self) { digit in
                        Button(digit) { model.sendDigit(digit) }
                    }
                }
            }

            GroupBox("Devices") {
                VStack(alignment: .leading) {
                    Picker("Speaker", selection: speakerBinding) {
                        Text("System output").tag(UInt32?.none)
                        ForEach(model.devices.filter { $0.outputChannels > 0 }) { device in
                            Text(device.isPresent ? device.name : "\(device.name) (unplugged)").tag(UInt32?.some(device.id))
                        }
                    }
                    Text("The microphone is the system input and the ring plays on the speaker: on macOS the call's voice-processing unit holds both halves, and cancels the speaker's echo\(model.echoCancelled ? " (on)" : "").")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    HStack {
                        Toggle("Mute microphone", isOn: microphoneMutedBinding)
                        Slider(value: microphoneGainBinding, in: 0...2) { Text("Mic gain") }
                        ProgressView(value: model.inputLevel).frame(width: 80)
                    }
                    HStack {
                        Toggle("Mute speaker", isOn: speakerMutedBinding)
                        Slider(value: speakerVolumeBinding, in: 0...2) { Text("Volume") }
                        ProgressView(value: model.outputLevel).frame(width: 80)
                    }
                }
            }

            GroupBox("Log") {
                ScrollView {
                    VStack(alignment: .leading) {
                        ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.caption, design: .monospaced))
                        }
                    }
                }
                .frame(minHeight: 120)
            }
        }
        .padding()
        .frame(minWidth: 480, minHeight: 640)
        .onAppear { model.start() }
    }

    private var speakerBinding: Binding<UInt32?> {
        Binding(get: { model.speaker }, set: { model.selectSpeaker($0) })
    }

    private var microphoneMutedBinding: Binding<Bool> {
        Binding(get: { model.microphoneMuted }, set: { model.setMicrophoneMuted($0) })
    }

    private var speakerMutedBinding: Binding<Bool> {
        Binding(get: { model.speakerMuted }, set: { model.setSpeakerMuted($0) })
    }

    private var microphoneGainBinding: Binding<Double> {
        Binding(get: { model.microphoneGain }, set: { model.setMicrophoneGain($0) })
    }

    private var speakerVolumeBinding: Binding<Double> {
        Binding(get: { model.speakerVolume }, set: { model.setSpeakerVolume($0) })
    }

    private var statusText: String {
        switch model.status {
        case .idle: return ""
        case .registering: return "registering…"
        case .registered: return "registered"
        case .failed(let message): return "failed: \(message)"
        }
    }
}
