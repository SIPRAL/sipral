// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI

/// A skeleton macOS sample. The library runs the audio; the first call
/// triggers the microphone prompt for whatever launched it.
@main
struct SipralSampleApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
