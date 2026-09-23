// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import SwiftUI

/// A skeleton macOS sample for the Swift layer over `sipral.h`: not a
/// product, and not run against the network from this Mac -- new binaries
/// reaching out wait on a network-filter popup nobody answers here, so this
/// is built and read, never launched against a real registrar from this
/// machine.
@main
struct SipralSampleApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
