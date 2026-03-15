import Cocoa

enum ANViewSlideDirection: Int {
    case forward
    case backward
}

internal func ErrorInfo(errorCode: Int) {
    runAlert("Error", "Error Code: \(errorCode)")
}

//@NSApplicationMain
class JWAppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet weak var window: NSWindow!

    var activeView: NSView?
    var nextView: NSView?
    var animating = false
    var networkList: JWListView?

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        print("JWDelegate: Launch Complete.")

        if UserDefaults.standard.dictionary(forKey: "USER_SCAN_OPTIONS") == nil {
            UserDefaults.standard.set(["SCAN_MERGE": kCFBooleanFalse], forKey: "USER_SCAN_OPTIONS")
        }

        window.isMovableByWindowBackground = true
        window.styleMask.insert([.fullSizeContentView, .unifiedTitleAndToolbar])
        window.titlebarAppearsTransparent = true
        networkList = JWListView(frame: window.contentView?.bounds ?? NSRect.null)
        push(networkList, direction: .forward)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ theApplication: NSApplication) -> Bool {
        return true
    }

    func push(_ view: NSView?, direction: ANViewSlideDirection) {
        if animating {
            return
        }
        weak var weakSelf = self
        var oldDestFrame = activeView?.bounds
        if direction == .forward {
            let width = 0 - (oldDestFrame?.size.width ?? 0)
            oldDestFrame?.origin.x = width
        } else {
            let width = oldDestFrame!.size.width
            oldDestFrame?.origin.x = width
        }

        var newSourceFrame = window.contentView?.bounds
        let newDestFrame = window.contentView?.bounds

        if direction == .forward {
            let width = newSourceFrame!.size.width
            newSourceFrame?.origin.x = width
        } else {
            let width = 0 - (newSourceFrame?.size.width ?? 0)
            newSourceFrame?.origin.x = width
        }

        animating = true

        view?.frame = newSourceFrame!
        if let view = view {
            window.contentView?.addSubview(view)
        }
        nextView = view

        NSAnimationContext.current.duration = 0.3
        NSAnimationContext.current.completionHandler = {
            weakSelf?.animationComplete()
        }
        NSAnimationContext.beginGrouping()
        activeView?.animator().frame = oldDestFrame!
        view?.animator().frame = newDestFrame!
        NSAnimationContext.endGrouping()
    }

    func animationComplete() {
        activeView?.removeFromSuperview()
        animating = false
        activeView = nextView
        nextView = nil
    }

    func showNetworkList() {
        push(networkList, direction: .backward)
    }

    func applicationWillTerminate(_ aNotification: Notification) {
    }

    @IBAction func preferencesPressed(_ sender: Any) {
        JWPreferences.shared.show()
    }
}
