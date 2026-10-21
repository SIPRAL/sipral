// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import SwiftUI
import UIKit

/// Creates the phone before `didFinishLaunching` returns: a launch caused
/// by a VoIP push must have PushKit's delegate in place by then, or the
/// push that woke it is lost.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate {
    let phone = PhoneModel()

    func application(
        _ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        phone.launch()
        return true
    }
}

@main
struct SipralPhoneApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(delegate.phone)
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .background: delegate.phone.scene(active: false)
            case .active: delegate.phone.scene(active: true)
            default: break
            }
        }
    }
}
