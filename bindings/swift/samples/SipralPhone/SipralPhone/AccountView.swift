// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI

struct AccountView: View {
    @EnvironmentObject private var phone: PhoneModel

    private var port: Binding<String> {
        Binding(
            get: { String(phone.settings.port) },
            set: { phone.settings.port = UInt16($0.filter(\.isNumber)) ?? 0 }
        )
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    RegistrationBadge(registration: phone.registration)
                }
                Section("Server") {
                    field("Server name or address", text: $phone.settings.server)
                    TextField("Port", text: port).keyboardType(.numberPad)
                    Picker("Transport", selection: $phone.settings.transport) {
                        ForEach(SignallingChoice.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    Toggle("Register", isOn: $phone.settings.registers)
                }
                Section("Account") {
                    field("User (extension)", text: $phone.settings.user)
                    SecureField("Password", text: $phone.password)
                    field("Authentication user, if not the user", text: $phone.settings.authUser)
                    field("Domain, if not the server's name", text: $phone.settings.domain)
                    TextField("Display name", text: $phone.settings.displayName)
                }
                Section("Media") {
                    Picker("SRTP", selection: $phone.settings.srtp) {
                        ForEach(SrtpChoice.allCases) { Text($0.rawValue).tag($0) }
                    }
                    field("STUN server, host:port", text: $phone.settings.stunServer)
                }
                Section {
                    Button("Save and register") { phone.saveAndRegister() }
                        .disabled(!phone.settings.isComplete)
                    Button("Unregister", role: .destructive) { phone.unregister() }
                } footer: {
                    Text("The password is kept in the keychain, on this phone only.")
                }
            }
            .navigationTitle("Account")
        }
        .navigationViewStyle(.stack)
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text)
            .textInputAutocapitalization(.never)
            .disableAutocorrection(true)
    }
}
