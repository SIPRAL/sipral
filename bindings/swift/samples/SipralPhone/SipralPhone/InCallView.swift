// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import AVKit
import SwiftUI

struct InCallView: View {
    @EnvironmentObject private var phone: PhoneModel
    @ObservedObject var session: CallSession
    @State private var keypad = false

    private let keys = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["*", "0", "#"]]

    var body: some View {
        VStack(spacing: 20) {
            VStack(spacing: 6) {
                Text(session.remote).font(.title3).multilineTextAlignment(.center)
                Text(session.state).font(.subheadline).foregroundColor(.secondary)
                if let confirmed = session.confirmedAt {
                    Text("Up since \(EvidenceLog.timestamp(confirmed))").font(.caption).foregroundColor(.secondary)
                }
                Text(session.statistics).font(.caption.monospacedDigit())
                Text("Audio \(session.audioState), \(session.route)").font(.caption).foregroundColor(.secondary)
            }
            .padding(.top, 40)
            if keypad {
                VStack(spacing: 12) {
                    Text(session.digits).font(.title2.monospacedDigit())
                    ForEach(keys, id: \.self) { row in
                        HStack(spacing: 20) {
                            ForEach(row, id: \.self) { key in
                                Button(key) { phone.sendDigits(key) }
                                    .font(.title2)
                                    .frame(width: 64, height: 64)
                                    .background(Circle().fill(Color(.secondarySystemBackground)))
                            }
                        }
                    }
                }
            }
            Spacer()
            HStack(spacing: 28) {
                toggle("Mute", "mic.slash.fill", session.muted) { phone.setMuted(!session.muted) }
                toggle("Hold", "pause.fill", session.held) { phone.setHeld(!session.held) }
                toggle("Keypad", "circle.grid.3x3.fill", keypad) { keypad.toggle() }
                toggle("Speaker", "speaker.wave.3.fill", session.speaker) { phone.setSpeaker(!session.speaker) }
            }
            HStack(spacing: 28) {
                RoutePicker()
                    .frame(width: 44, height: 44)
                    .accessibilityLabel("Audio route")
                Button {
                    phone.hangUp()
                } label: {
                    Image(systemName: "phone.down.fill")
                        .font(.title)
                        .foregroundColor(.white)
                        .frame(width: 72, height: 72)
                        .background(Circle().fill(Color.red))
                }
                .accessibilityLabel("Hang up")
            }
            .padding(.bottom, 32)
        }
        .padding(.horizontal)
    }

    private func toggle(_ title: String, _ image: String, _ on: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: image)
                    .font(.title2)
                    .frame(width: 56, height: 56)
                    .background(Circle().fill(on ? Color.accentColor.opacity(0.3) : Color(.secondarySystemBackground)))
                Text(title).font(.caption)
            }
        }
        .accessibilityValue(on ? "on" : "off")
    }
}

/// The system's own route picker: earpiece, speaker, a wired or Bluetooth
/// headset, CarPlay, whatever the session can reach.
struct RoutePicker: UIViewRepresentable {
    func makeUIView(context: Context) -> AVRoutePickerView {
        let picker = AVRoutePickerView()
        picker.prioritizesVideoDevices = false
        return picker
    }

    func updateUIView(_ uiView: AVRoutePickerView, context: Context) {}
}
