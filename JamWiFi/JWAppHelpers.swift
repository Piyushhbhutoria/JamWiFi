import AppKit
import SwiftUI

/// Shared alert state for SwiftUI alerts; pass as @EnvironmentObject.
final class AppAlertState: ObservableObject {
    @Published var title = ""
    @Published var message = ""
    @Published var isPresented = false
    @Published var isAdminError = false

    func show(title: String, message: String) {
        self.title = title
        self.message = message
        self.isAdminError = false
        self.isPresented = true
    }

    func showAdminError(title: String, message: String) {
        self.title = title
        self.message = message
        self.isAdminError = true
        self.isPresented = true
    }
}

/// When not running as root: requests admin via AppleScript; on failure sets adminErrorMessage and returns so the app can show a SwiftUI alert then exit.
@objcMembers final class JWAppRunner: NSObject {
    static var adminErrorMessage: String?

    static func requestAdminAndExitIfNeeded() {
        guard let execPath = Bundle.main.executablePath else { return }
        let script = "do shell script quoted form of \"\(execPath)\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        if error != nil {
            adminErrorMessage = "This program cannot tap into the wireless network stack without administrator access."
            return
        }
        exit(0)
    }
}
