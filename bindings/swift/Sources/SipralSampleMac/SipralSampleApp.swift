// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI

/// A skeleton macOS sample for the Swift layer over `sipral.h`: not a
/// product. The library runs its audio -- `AppModel` holds no audio code --
/// and the first call asks the system for the microphone, on behalf of
/// whatever launched the sample (a Terminal, for `swift run`).
@main
struct SipralSampleApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
