import SwiftUI

@main
struct JamWiFiApp: App {
    @NSApplicationDelegateAdaptor(JWAppDelegate.self) private var delegate
    @StateObject private var navigation = AppNavigation()
    @StateObject private var alertState = AppAlertState()
    @StateObject private var preferencesStore = PreferencesStore()

    init() {
        if CommandLine.arguments.contains("--scan-mode") {
            JWScanModeRunner.run()
            exit(0)
        }
        if geteuid() != 0 {
            JWAppRunner.requestAdminAndExitIfNeeded()
        }
        if UserDefaults.standard.dictionary(forKey: "USER_SCAN_OPTIONS") == nil {
            UserDefaults.standard.set(["SCAN_MERGE": false], forKey: "USER_SCAN_OPTIONS")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView(navigation: navigation)
                .environmentObject(alertState)
                .frame(minWidth: 640, minHeight: 400)
                .onAppear {
                    if let msg = JWAppRunner.adminErrorMessage {
                        alertState.showAdminError(title: "Cannot run without admin privileges", message: msg)
                        JWAppRunner.adminErrorMessage = nil
                    }
                }
        }
        .windowStyle(.automatic)
        .defaultSize(width: 900, height: 600)
        Settings {
            JWPreferencesScreen(store: preferencesStore)
        }
    }
}
