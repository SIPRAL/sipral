// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import SwiftUI
import Sipral

/// A skeleton, not a product: registration, a call, hold, DTMF, devices --
/// the five things `THE TASK` asks the sample to show, in one window.
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
                Text("Microphone and speaker are the system default input/output, bridged through AVAudioEngine (AudioBridge.swift). Choosing a device is macOS's own Sound settings in this skeleton.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
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
        .frame(minWidth: 420, minHeight: 560)
        .onAppear { model.start() }
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
