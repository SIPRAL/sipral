// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var phone: PhoneModel

    var body: some View {
        TabView {
            DialView()
                .tabItem { Label("Phone", systemImage: "circle.grid.3x3.fill") }
            AccountView()
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
            DiagnosticsView()
                .tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
        }
        .fullScreenCover(isPresented: Binding(get: { phone.session != nil }, set: { _ in })) {
            if let session = phone.session {
                InCallView(session: session)
                    .environmentObject(phone)
            }
        }
        .sheet(isPresented: Binding(get: { phone.offer != nil && phone.session == nil }, set: { _ in })) {
            if let offer = phone.offer {
                IncomingView(offer: offer)
                    .environmentObject(phone)
            }
        }
    }
}

/// The registration, as a line of colour and text.
struct RegistrationBadge: View {
    let registration: PhoneModel.Registration

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(color).frame(width: 10, height: 10)
            Text(registration.text).font(.footnote).lineLimit(2)
        }
        .accessibilityElement(children: .combine)
    }

    private var color: Color {
        switch registration {
        case .registered: return .green
        case .registering: return .orange
        case .failed: return .red
        case .off: return .gray
        }
    }
}

struct DialView: View {
    @EnvironmentObject private var phone: PhoneModel
    @State private var typed = ""

    private let keys = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["*", "0", "#"]]

    var body: some View {
        VStack(spacing: 16) {
            RegistrationBadge(registration: phone.registration)
                .padding(.top)
            TextField("Number or SIP address", text: $typed)
                .font(.title2)
                .multilineTextAlignment(.center)
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .keyboardType(.asciiCapable)
                .padding(.horizontal)
            ForEach(keys, id: \.self) { row in
                HStack(spacing: 24) {
                    ForEach(row, id: \.self) { key in
                        Button(key) { typed += key }
                            .font(.title)
                            .frame(width: 72, height: 72)
                            .background(Circle().fill(Color(.secondarySystemBackground)))
                    }
                }
            }
            HStack(spacing: 24) {
                Button {
                    phone.dial(typed)
                } label: {
                    Image(systemName: "phone.fill")
                        .font(.title)
                        .foregroundColor(.white)
                        .frame(width: 72, height: 72)
                        .background(Circle().fill(Color.green))
                }
                .disabled(typed.isEmpty || !phone.canDial)
                .accessibilityLabel("Call")
                Button {
                    if !typed.isEmpty { typed.removeLast() }
                } label: {
                    Image(systemName: "delete.left").font(.title2).frame(width: 72, height: 72)
                }
                .accessibilityLabel("Delete")
            }
            Spacer()
        }
    }
}

struct IncomingView: View {
    @EnvironmentObject private var phone: PhoneModel
    let offer: IncomingOffer

    var body: some View {
        VStack(spacing: 24) {
            Text("Incoming call").font(.headline)
            Text(offer.caller).font(.title2).multilineTextAlignment(.center)
            HStack(spacing: 48) {
                Button("Decline", role: .destructive) { phone.decline() }
                    .buttonStyle(.borderedProminent)
                Button("Answer") { phone.answer() }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
            }
        }
        .padding()
    }
}
