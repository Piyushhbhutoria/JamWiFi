import Cocoa
import CoreWLAN
import SystemConfiguration
import Darwin

class JWListView: NSView, NSTableViewDelegate, NSTableViewDataSource {
    var interfaceName = ""
    var networks: [JWScanResult] = []
    var scanButton: NSButton?
    var joinButton: NSButton?
    var disassociateButton: NSButton?
    var jamButton: NSButton?
    var progressIndicator: NSProgressIndicator?
    var networksScrollView: NSScrollView?
    var networksTable: NSTableView?

    var sortAscending = true
    var sortOrder = ""

    override init(frame: NSRect) {
        super.init(frame: frame)

        networksScrollView = NSScrollView(frame: NSRect(x: 10, y: 52, width: frame.size.width - 20, height: frame.size.height - 62))
        networksTable = NSTableView(frame: networksScrollView?.contentView.bounds ?? NSRect.zero)
        disassociateButton = NSButton(frame: NSRect(x: 10, y: 10, width: 100, height: 24))
        joinButton = NSButton(frame: NSRect(x: 110, y: 10, width: 100, height: 24))
        scanButton = NSButton(frame: NSRect(x: 210, y: 10, width: 100, height: 24))
        progressIndicator = NSProgressIndicator(frame: NSRect(x: 325, y: 14, width: 16, height: 16))
        jamButton = NSButton(frame: NSRect(x: frame.size.width - 110, y: 10, width: 100, height: 24))

        progressIndicator?.controlSize = .small
        progressIndicator?.style = .spinning
        progressIndicator?.isDisplayedWhenStopped = false

        scanButton?.bezelStyle = .rounded
        scanButton?.title = "Scan"
        scanButton?.target = self
        scanButton?.action = #selector(scanButton(_:))
        scanButton?.font = NSFont.systemFont(ofSize: 13)

        joinButton?.bezelStyle = .rounded
        joinButton?.title = "Join"
        joinButton?.target = self
        joinButton?.action = #selector(joinButton(_:))
        joinButton?.font = NSFont.systemFont(ofSize: 13)
        joinButton?.isEnabled = false

        disassociateButton?.bezelStyle = .rounded
        disassociateButton?.title = "Deauth"
        disassociateButton?.target = self
        disassociateButton?.action = #selector(disassociateButton(_:))
        disassociateButton?.font = NSFont.systemFont(ofSize: 13)

        jamButton?.bezelStyle = .rounded
        jamButton?.title = "Monitor"
        jamButton?.target = self
        jamButton?.action = #selector(jamButton(_:))
        jamButton?.font = NSFont.systemFont(ofSize: 13)
        jamButton?.isEnabled = false

        let channelColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("channel"))
        channelColumn.headerCell.stringValue = "CH"
        channelColumn.width = 40
        channelColumn.isEditable = true
        channelColumn.sortDescriptorPrototype = NSSortDescriptor(key: channelColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(channelColumn)

        let essidColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("essid"))
        essidColumn.headerCell.stringValue = "ESSID"
        essidColumn.width = 170
        essidColumn.isEditable = true
        essidColumn.sortDescriptorPrototype = NSSortDescriptor(key: essidColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(essidColumn)

        let bssidColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("bssid"))
        bssidColumn.headerCell.stringValue = "BSSID"
        bssidColumn.width = 120
        bssidColumn.isEditable = true
        bssidColumn.sortDescriptorPrototype = NSSortDescriptor(key: bssidColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(bssidColumn)

        let encColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("enc"))
        encColumn.headerCell.stringValue = "Security"
        encColumn.width = 160
        encColumn.isEditable = true
        encColumn.sortDescriptorPrototype = NSSortDescriptor(key: encColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(encColumn)

        let rssiColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("rssi"))
        rssiColumn.headerCell.stringValue = "RSSI"
        rssiColumn.width = 40
        rssiColumn.isEditable = true
        rssiColumn.sortDescriptorPrototype = NSSortDescriptor(key: rssiColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(rssiColumn)

        let channelBandColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("channelBand"))
        channelBandColumn.headerCell.stringValue = "CH-Band"
        channelBandColumn.width = 60
        channelBandColumn.isEditable = true
        channelBandColumn.sortDescriptorPrototype = NSSortDescriptor(key: channelBandColumn.identifier.rawValue, ascending: true)
        networksTable?.addTableColumn(channelBandColumn)

        networksScrollView?.documentView = networksTable
        networksScrollView?.borderType = .bezelBorder
        networksScrollView?.hasVerticalScroller = true
        networksScrollView?.hasHorizontalScroller = false
        networksScrollView?.autohidesScrollers = false

        networksTable?.dataSource = self
        networksTable?.delegate = self
        networksTable?.allowsMultipleSelection = true
        networksTable?.refusesFirstResponder = true

        if let v = networksScrollView  { addSubview(v) }
        if let v = scanButton          { addSubview(v) }
        if let v = joinButton          { addSubview(v) }
        if let v = disassociateButton  { addSubview(v) }
        if let v = progressIndicator   { addSubview(v) }
        if let v = jamButton           { addSubview(v) }

        autoresizesSubviews = true
        autoresizingMask = [.width, .height]
        networksScrollView?.autoresizingMask = [.width, .height]
        jamButton?.autoresizingMask = .minXMargin
    }

    required init?(coder decoder: NSCoder) {
        super.init(coder: decoder)
    }

    // MARK: - Button actions -

    @objc func scanButton(_ sender: Any?) {
        progressIndicator?.startAnimation(self)
        scanButton?.isEnabled = false
        scanInBackground()
    }

    @objc func sheetOkPressed(_ sender: Any?) {
        self.window?.endSheet((sender as! NSView).window!, returnCode: .OK)
    }
    @objc func sheetCancelPressed(_ sender: Any?) {
        self.window?.endSheet((sender as! NSView).window!, returnCode: .cancel)
    }

    @objc func joinButton(_ sender: Any?) {
        progressIndicator?.startAnimation(self)
        joinButton?.isEnabled = false
        let network = self.networks[(networksTable?.selectedRowIndexes.first)!]
        var password = ""

        let done: ((Bool) -> ()) = { run in
            if run {
                guard let iface = CWWiFiClient.shared().interface() else {
                    DispatchQueue.main.async {
                        self.progressIndicator?.stopAnimation(self)
                        self.joinButton?.isEnabled = true
                        runAlert("Join Failed", "No Wi-Fi interface found.")
                    }
                    return
                }
                self.interfaceName = iface.interfaceName ?? "en0"
                // Reconstruct a CWNetwork via a targeted scan so CWInterface.associate can use it.
                let matched = (try? iface.scanForNetworks(withName: network.ssid))?.first {
                    $0.bssid == network.bssid
                }
                if let cwNet = matched {
                    do {
                        try iface.associate(to: cwNet, password: password.isEmpty ? nil : password)
                        print("Join success")
                    } catch {
                        print("Join failed: \(error)")
                    }
                }
            }
            DispatchQueue.main.async {
                self.progressIndicator?.stopAnimation(self)
                self.joinButton?.isEnabled = true
            }
        }

        if network.supportsSecurity(.none) == false {
            let sheetWindow = NSWindow(
                contentRect: NSMakeRect(0, 0, 300, 100),
                styleMask: [.titled],
                backing: .buffered,
                defer: false
            )
            let label = NSTextField(labelWithString: "Enter Password:")
            label.frame = NSMakeRect(13, sheetWindow.frame.height - label.frame.height - 12,
                                     label.frame.width, label.frame.height)

            let passwordField = NSTextField(frame: NSRect(x: label.frame.origin.x + 2, y: 38, width: 270, height: 24))
            passwordField.placeholderString = "Password"
            passwordField.target = self
            passwordField.action = #selector(sheetOkPressed(_:))

            let cancelButton = NSButton(frame: NSRect(x: sheetWindow.frame.width - 70 - 6, y: 5, width: 70, height: 24))
            let okButton     = NSButton(frame: NSRect(x: cancelButton.frame.origin.x - 70, y: 5, width: 70, height: 24))

            cancelButton.bezelStyle = .rounded
            cancelButton.title = "Cancel"
            cancelButton.target = self
            cancelButton.action = #selector(sheetCancelPressed(_:))

            okButton.bezelStyle = .rounded
            okButton.title = "Try"
            okButton.target = self
            okButton.action = #selector(sheetOkPressed(_:))
            okButton.isHighlighted = true

            sheetWindow.contentView?.addSubview(label)
            sheetWindow.contentView?.addSubview(passwordField)
            sheetWindow.contentView?.addSubview(okButton)
            sheetWindow.contentView?.addSubview(cancelButton)

            self.window?.beginSheet(sheetWindow, completionHandler: { response in
                password = passwordField.stringValue
                DispatchQueue.global(qos: .userInitiated).async { done(response == .OK) }
            })
        } else {
            DispatchQueue.global(qos: .userInitiated).async { done(true) }
        }
    }

    @objc func disassociateButton(_ sender: Any?) {
        CWWiFiClient.shared().interface()?.disassociate()
    }

    @objc func jamButton(_ sender: Any?) {
        var theNetworks: [JWScanResult] = []
        for idx in networksTable?.selectedRowIndexes ?? [] {
            theNetworks.append(self.networks[idx])
        }
        let sniffer = ANWiFiSniffer(interfaceName: interfaceName)
        let gatherer = JWTrafficGatherer(frame: bounds, sniffer: sniffer, networks: theNetworks)
        (NSApp.delegate as? JWAppDelegate)?.push(gatherer, direction: .forward)
    }

    // MARK: - Scanning -

    func scanInBackground() {
        DispatchQueue.global(qos: .default).async {
            guard let iface = CWWiFiClient.shared().interface() else {
                self.performSelector(onMainThread: #selector(self.handleScanError),
                                     with: nil, waitUntilDone: false)
                return
            }
            self.interfaceName = iface.interfaceName ?? "en0"

            if let beaconResults = JWListView.scanViaBeaconFrames(interfaceName: self.interfaceName,
                                                                  supportedChannels: iface.supportedWLANChannels() ?? []),
               !beaconResults.isEmpty {
                self.performSelector(onMainThread: #selector(self.handleScanSuccess(_:)),
                                     with: beaconResults, waitUntilDone: false)
                return
            }

            // Apple80211Scan bypasses both the root-process SSID restriction and the
            // Location Services requirement — it's the same API the original app used.
            // The framework is already linked so dlopen finds it without loading.
            if let cwNetworks = JWListView.scanViaApple80211(interfaceName: self.interfaceName),
               !cwNetworks.isEmpty {
                let results = cwNetworks.map { JWScanResult.from(cwNetwork: $0) }
                self.performSelector(onMainThread: #selector(self.handleScanSuccess(_:)),
                                     with: results, waitUntilDone: false)
                return
            }

            // Fallback: spawn a child process as the console user so CoreWLAN returns
            // real SSIDs (works when the user has granted Location Services permission).
            var uid: uid_t = 0
            var gid: gid_t = 0
            let store = SCDynamicStoreCreate(kCFAllocatorDefault, "JamWiFi" as CFString, nil, nil)
            _ = SCDynamicStoreCopyConsoleUser(store, &uid, &gid)

            guard uid != 0, let execPath = Bundle.main.executablePath else {
                self.performSelector(onMainThread: #selector(self.handleScanError),
                                     with: nil, waitUntilDone: false)
                return
            }

            var childPid: pid_t = 0
            let readFd = execPath.withCString { cPath in
                spawnScanSubprocess(cPath, uid, gid, &childPid)
            }
            guard readFd >= 0 else {
                self.performSelector(onMainThread: #selector(self.handleScanError),
                                     with: nil, waitUntilDone: false)
                return
            }

            let fh = FileHandle(fileDescriptor: readFd, closeOnDealloc: true)
            let data = fh.readDataToEndOfFile()
            var status: Int32 = 0
            waitpid(childPid, &status, 0)

            guard !data.isEmpty,
                  let jsonArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                self.performSelector(onMainThread: #selector(self.handleScanError),
                                     with: nil, waitUntilDone: false)
                return
            }

            let scanned = jsonArray.compactMap { JWScanResult.from(dict: $0) }
            self.performSelector(onMainThread: #selector(self.handleScanSuccess(_:)),
                                 with: scanned, waitUntilDone: false)
        }
    }

    // Calls Apple80211Scan via dlopen — the framework is already linked so this is
    // just a lookup, not a fresh load.  Returns nil if any symbol is unavailable.
    private static func scanViaApple80211(interfaceName: String) -> [CWNetwork]? {
        let path = "/System/Library/PrivateFrameworks/Apple80211.framework/Apple80211"
        // RTLD_NOLOAD: only succeeds if already in memory (it is — it's linked).
        // If somehow not loaded, fall back to a normal open.
        guard let fwHandle = dlopen(path, RTLD_NOLOAD | RTLD_NOW)
                          ?? dlopen(path, RTLD_LAZY) else { return nil }
        defer { dlclose(fwHandle) }

        typealias OpenFn  = @convention(c) (UnsafeMutablePointer<UnsafeMutableRawPointer?>) -> Int32
        typealias BindFn  = @convention(c) (UnsafeMutableRawPointer?, CFString) -> Int32
        typealias ScanFn  = @convention(c) (UnsafeMutableRawPointer?,
                                            UnsafeMutablePointer<Unmanaged<CFArray>?>,
                                            CFDictionary) -> Int32
        typealias CloseFn = @convention(c) (UnsafeMutableRawPointer?) -> Int32

        guard let openPtr  = dlsym(fwHandle, "Apple80211Open"),
              let bindPtr  = dlsym(fwHandle, "Apple80211BindToInterface"),
              let scanPtr  = dlsym(fwHandle, "Apple80211Scan"),
              let closePtr = dlsym(fwHandle, "Apple80211Close") else { return nil }

        let open80211  = unsafeBitCast(openPtr,  to: OpenFn.self)
        let bind80211  = unsafeBitCast(bindPtr,  to: BindFn.self)
        let scan80211  = unsafeBitCast(scanPtr,  to: ScanFn.self)
        let close80211 = unsafeBitCast(closePtr, to: CloseFn.self)

        var wh: UnsafeMutableRawPointer? = nil
        guard open80211(&wh) == 0, let wifiHandle = wh else { return nil }
        defer { close80211(wifiHandle) }

        bind80211(wifiHandle, interfaceName as CFString)

        var rawList: Unmanaged<CFArray>? = nil
        scan80211(wifiHandle, &rawList, [:] as CFDictionary)
        return rawList?.takeRetainedValue() as? [CWNetwork]
    }

    private static func scanViaBeaconFrames(interfaceName: String,
                                            supportedChannels: Set<CWChannel>) -> [JWScanResult]? {
        guard let tap = ANInterface(interface: interfaceName) else { return nil }
        defer { tap.closeInterface() }

        let channels = supportedChannels.sorted {
            if $0.channelNumber == $1.channelNumber {
                return $0.channelBand.rawValue < $1.channelBand.rawValue
            }
            return $0.channelNumber < $1.channelNumber
        }

        var networksByKey: [String: JWScanResult] = [:]
        for channel in channels {
            guard tap.setChannel(channel.channelNumber) else { continue }

            let dwellTime: TimeInterval = channel.channelBand == .band2GHz ? 0.18 : 0.12
            let deadline = Date(timeIntervalSinceNow: dwellTime)
            repeat {
                autoreleasepool {
                    guard let packet = tap.nextPacket(false) else { return }
                    let frameControl = Int(packet.packetData()[0])
                    let type = (frameControl >> 2) & 0x3
                    let subtype = (frameControl >> 4) & 0xF
                    guard type == 0, subtype == 8 || subtype == 5,
                          let result = JWScanResult.from(beaconPacket: packet,
                                                         supportedChannels: supportedChannels) else {
                        return
                    }

                    let key = result.bssid ?? "\(result.channelBandRaw):\(result.channelNumber):\(result.ssid ?? "<Hidden>")"
                    if let existing = networksByKey[key], existing.rssiValue >= result.rssiValue {
                        return
                    }
                    networksByKey[key] = result
                }
            } while Date() < deadline
        }
        return Array(networksByKey.values)
    }

    // MARK: - Table View -

    func numberOfRows(in tableView: NSTableView) -> Int { networks.count }

    func tableView(_ tableView: NSTableView, objectValueFor tableColumn: NSTableColumn?, row: Int) -> Any? {
        let network = networks[row]
        switch tableColumn?.identifier.rawValue {
        case "channelBand":
            switch network.channelBandRaw {
            case CWChannelBand.band2GHz.rawValue: return "2.4 GHz"
            case CWChannelBand.band5GHz.rawValue: return "5 GHz"
            default: return network.channelBandRaw == 0 ? "?" : "\(network.channelBandRaw) GHz"
            }
        case "channel": return NSNumber(value: network.channelNumber)
        case "essid":   return network.ssid ?? "<Hidden>"
        case "bssid":   return network.bssid ?? ""
        case "enc":     return securityTypeString(network)
        case "rssi":    return NSNumber(value: network.rssiValue).description
        default:        return nil
        }
    }

    func tableView(_ tableView: NSTableView, setObjectValue object: Any?, for tableColumn: NSTableColumn?, row: Int) {}

    func tableViewSelectionDidChange(_ notification: Notification) {
        let count = networksTable?.selectedRowIndexes.count ?? 0
        jamButton?.isEnabled  = count > 0
        joinButton?.isEnabled = count == 1
    }

    func securityTypeString(_ network: JWScanResult?) -> String {
        guard let network = network else { return "?" }
        if network.supportsSecurity(.none) { return "Open" }
        var parts: [String] = []
        if network.supportsSecurity(.WEP)          { parts.append("WEP") }
        if network.supportsSecurity(.dynamicWEP)   { parts.append("Dynamic WEP") }
        if network.supportsSecurity(.wpaPersonal)  { parts.append("WPA (P)") }
        if network.supportsSecurity(.wpa2Personal) { parts.append("WPA2 (P)") }
        if network.supportsSecurity(.wpaEnterprise)  { parts.append("WPA (E)") }
        if network.supportsSecurity(.wpa2Enterprise) { parts.append("WPA2 (E)") }
        if network.supportsSecurity(.unknown)      { parts.append("Unknown") }
        return parts.isEmpty ? "?" : parts.joined(separator: " / ")
    }

    func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
        guard let sortDescriptor = tableView.sortDescriptors.first else { return }
        sortAscending = sortDescriptor.ascending
        sortOrder = sortDescriptor.key!
        sortNetworks()
        networksTable?.reloadData()
    }

    func sortNetworks() {
        if sortOrder.isEmpty { return }
        let order: ComparisonResult = sortAscending ? .orderedAscending : .orderedDescending
        switch sortOrder {
        case "channelBand": networks.sort { String($0.channelBandRaw).localizedStandardCompare(String($1.channelBandRaw)) == order }
        case "channel":     networks.sort { String($0.channelNumber).localizedStandardCompare(String($1.channelNumber)) == order }
        case "essid":       networks.sort { ($0.ssid ?? "<Hidden>").localizedStandardCompare($1.ssid ?? "<Hidden>") == order }
        case "bssid":       networks.sort { ($0.bssid ?? "").localizedStandardCompare($1.bssid ?? "") == order }
        case "enc":         networks.sort { securityTypeString($0).localizedStandardCompare(securityTypeString($1)) == order }
        case "rssi":        networks.sort { String($0.rssiValue).localizedStandardCompare(String($1.rssiValue)) == order }
        default: break
        }
    }

    // MARK: - Private -

    @objc private func handleScanError() {
        progressIndicator?.stopAnimation(self)
        scanButton?.isEnabled = true
        runAlert("Scan Failed", "A network scan could not be completed at this time.")
    }

    @objc private func handleScanSuccess(_ theNetworks: [JWScanResult]?) {
        var newNetworks = theNetworks ?? []
        outerLoop: for existing in networks {
            for n in newNetworks where isNetworkEqual(existing, n) { continue outerLoop }
            newNetworks.append(existing)
        }
        progressIndicator?.stopAnimation(self)
        scanButton?.isEnabled = true
        networks = newNetworks
        sortNetworks()
        networksTable?.reloadData()
    }

    private func isNetworkEqual(_ a: JWScanResult, _ b: JWScanResult) -> Bool {
        return a.ssid == b.ssid && a.bssid == b.bssid &&
               a.channelNumber == b.channelNumber && a.channelBandRaw == b.channelBandRaw
    }
}
