// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI
import UIKit

struct DiagnosticsView: View {
    @EnvironmentObject private var phone: PhoneModel
    @State private var shared: SharedFile?

    var body: some View {
        NavigationView {
            List {
                Section("Now") {
                    row("Registration", phone.registration.text)
                    row("Local address", phone.localAddress)
                    row("Network", phone.networkText)
                    row("Push", phone.pushText)
                    row("Lifecycle", phone.lifecycleText)
                    if let session = phone.session {
                        row("Call", "\(session.remote), \(session.state), \(session.statistics)")
                    }
                }
                Section {
                    Toggle("Whole SIP messages", isOn: Binding(
                        get: { phone.wholeMessages },
                        set: { phone.setWholeMessages($0) }
                    ))
                    Toggle("Keep the screen on", isOn: Binding(
                        get: { phone.keepsScreenOn },
                        set: { phone.setKeepsScreenOn($0) }
                    ))
                    Button("Share log") {
                        if let url = phone.writeEvidence() {
                            shared = SharedFile(url: url)
                        }
                    }
                } footer: {
                    Text("One text file: this screen, every log line with its time, the stack's decision record and its state. The password and the stack's credentials are taken out.")
                }
                Section("Counters") {
                    Text(phone.countersText).font(.caption.monospaced())
                }
                Section("Log, newest last") {
                    ForEach(Array(phone.timeline.suffix(100).enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption2.monospaced())
                    }
                }
            }
            .navigationTitle("Diagnostics")
            .toolbar {
                Button("Refresh") { phone.refreshDiagnostics() }
            }
            .onAppear { phone.refreshDiagnostics() }
        }
        .navigationViewStyle(.stack)
        .sheet(item: $shared) { file in
            ShareSheet(items: [file.url])
        }
    }

    private func row(_ name: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(name).font(.caption).foregroundColor(.secondary)
            Text(value).font(.footnote).textSelection(.enabled)
        }
    }
}

struct SharedFile: Identifiable {
    let url: URL
    var id: URL { url }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
