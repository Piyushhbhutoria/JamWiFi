import Cocoa
import CoreWLAN
import SystemConfiguration
import Darwin
import SwiftUI
import Combine

final class JWListView: ObservableObject {
    weak var navigation: AppNavigation?
    weak var alertState: AppAlertState?

    @Published var interfaceName = ""
    @Published var networks: [JWScanResult] = []
    @Published var selectedNetworkIDs = Set<String>()
    @Published var isScanning = false
    @Published var headerStatsText = "No scan results yet"
    @Published var copyButtonTitle = "Copy BSSID"
    @Published var networkRequestingPassword: JWScanResult?

    private var sortAscending = true
    private var sortOrder = ""
    private var copyFeedbackResetWorkItem: DispatchWorkItem?

    init(navigation: AppNavigation?) {
        self.navigation = navigation
        updateHeaderStats()
    }

    func scanButton(_ sender: Any?) {
        isScanning = true
        scanInBackground()
    }

    func joinButton(_ sender: Any?) {
        guard let network = selectedNetworks.first else { return }
        if network.supportsSecurity(.none) == false {
            isScanning = true
            networkRequestingPassword = network
        } else {
            performJoin(to: network, password: "")
        }
    }

    func performJoin(to network: JWScanResult, password: String) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            defer { DispatchQueue.main.async { self.isScanning = false } }
            guard let iface = CWWiFiClient.shared().interface() else {
                DispatchQueue.main.async {
                    self.alertState?.show(title: "Join Failed", message: "No Wi-Fi interface found.")
                }
                return
            }
            DispatchQueue.main.async { self.interfaceName = iface.interfaceName ?? "en0" }
            let matched = (try? iface.scanForNetworks(withName: network.ssid))?.first { $0.bssid == network.bssid }
            if let cwNet = matched {
                do {
                    try iface.associate(to: cwNet, password: password.isEmpty ? nil : password)
                } catch {
                    print("Join failed: \(error)")
                }
            }
        }
    }

    /// Dismisses the password sheet and clears scanning (use for Cancel).
    func dismissJoinPasswordSheet() {
        networkRequestingPassword = nil
        isScanning = false
    }

    /// Closes the password sheet only; scanning is cleared when performJoin finishes (use for Try).
    func clearJoinPasswordSheet() {
        networkRequestingPassword = nil
    }

    func disassociateButton(_ sender: Any?) {
        CWWiFiClient.shared().interface()?.disassociate()
    }

    func jamButton(_ sender: Any?) {
        let sniffer = ANWiFiSniffer(interfaceName: interfaceName)
        let gatherer = JWTrafficGatherer(navigation: navigation, sniffer: sniffer, networks: selectedNetworks)
        navigation?.push(.gatherer(gatherer))
    }

    func copyBSSID(_ sender: Any?) {
        guard let bssid = selectedBSSID() else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(bssid, forType: .string)
        NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .now)
        animateCopyFeedback()
    }

    @objc func copy(_ sender: Any?) {
        copyBSSID(sender)
    }

    func scanInBackground() {
        DispatchQueue.global(qos: .default).async {
            guard let iface = CWWiFiClient.shared().interface() else {
                DispatchQueue.main.async { self.handleScanError() }
                return
            }
            self.interfaceName = iface.interfaceName ?? "en0"

            if let beaconResults = JWListView.scanViaBeaconFrames(interfaceName: self.interfaceName, supportedChannels: iface.supportedWLANChannels() ?? []), !beaconResults.isEmpty {
                DispatchQueue.main.async { self.handleScanSuccess(beaconResults) }
                return
            }

            if let cwNetworks = JWListView.scanViaApple80211(interfaceName: self.interfaceName), !cwNetworks.isEmpty {
                let results = cwNetworks.map { JWScanResult.from(cwNetwork: $0) }
                DispatchQueue.main.async { self.handleScanSuccess(results) }
                return
            }

            var uid: uid_t = 0
            var gid: uid_t = 0
            let store = SCDynamicStoreCreate(kCFAllocatorDefault, "JamWiFi" as CFString, nil, nil)
            _ = SCDynamicStoreCopyConsoleUser(store, &uid, &gid)

            guard uid != 0, let execPath = Bundle.main.executablePath else {
                DispatchQueue.main.async { self.handleScanError() }
                return
            }

            var childPid: pid_t = 0
            let readFd = execPath.withCString { cPath in
                spawnScanSubprocess(cPath, uid, gid, &childPid)
            }

            guard readFd >= 0 else {
                DispatchQueue.main.async { self.handleScanError() }
                return
            }

            let fileHandle = FileHandle(fileDescriptor: readFd, closeOnDealloc: true)
            let data = fileHandle.readDataToEndOfFile()
            var status: Int32 = 0
            waitpid(childPid, &status, 0)

            guard !data.isEmpty,
                  let jsonArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                DispatchQueue.main.async { self.handleScanError() }
                return
            }

            let scanned = jsonArray.compactMap { JWScanResult.from(dict: $0) }
            DispatchQueue.main.async { self.handleScanSuccess(scanned) }
        }
    }

    private static func scanViaApple80211(interfaceName: String) -> [CWNetwork]? {
        let path = "/System/Library/PrivateFrameworks/Apple80211.framework/Apple80211"
        guard let fwHandle = dlopen(path, RTLD_NOLOAD | RTLD_NOW) ?? dlopen(path, RTLD_LAZY) else { return nil }
        defer { dlclose(fwHandle) }

        typealias OpenFn = @convention(c) (UnsafeMutablePointer<UnsafeMutableRawPointer?>) -> Int32
        typealias BindFn = @convention(c) (UnsafeMutableRawPointer?, CFString) -> Int32
        typealias ScanFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<Unmanaged<CFArray>?>, CFDictionary) -> Int32
        typealias CloseFn = @convention(c) (UnsafeMutableRawPointer?) -> Int32

        guard let openPtr = dlsym(fwHandle, "Apple80211Open"),
              let bindPtr = dlsym(fwHandle, "Apple80211BindToInterface"),
              let scanPtr = dlsym(fwHandle, "Apple80211Scan"),
              let closePtr = dlsym(fwHandle, "Apple80211Close") else { return nil }

        let open80211 = unsafeBitCast(openPtr, to: OpenFn.self)
        let bind80211 = unsafeBitCast(bindPtr, to: BindFn.self)
        let scan80211 = unsafeBitCast(scanPtr, to: ScanFn.self)
        let close80211 = unsafeBitCast(closePtr, to: CloseFn.self)

        var wh: UnsafeMutableRawPointer? = nil
        guard open80211(&wh) == 0, let wifiHandle = wh else { return nil }
        defer { _ = close80211(wifiHandle) }

        _ = bind80211(wifiHandle, interfaceName as CFString)
        var rawList: Unmanaged<CFArray>? = nil
        _ = scan80211(wifiHandle, &rawList, [:] as CFDictionary)
        return rawList?.takeRetainedValue() as? [CWNetwork]
    }

    private static func scanViaBeaconFrames(interfaceName: String, supportedChannels: Set<CWChannel>) -> [JWScanResult]? {
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
            let deadline = Date(timeIntervalSinceNow: channel.channelBand == .band2GHz ? 0.18 : 0.12)
            repeat {
                autoreleasepool {
                    guard let packet = tap.nextPacket(false) else { return }
                    let frameControl = Int(packet.packetData()[0])
                    let type = (frameControl >> 2) & 0x3
                    let subtype = (frameControl >> 4) & 0xF
                    guard type == 0, subtype == 8 || subtype == 5,
                          let result = JWScanResult.from(beaconPacket: packet, supportedChannels: supportedChannels) else { return }
                    let key = result.bssid ?? "\(result.channelBandRaw):\(result.channelNumber):\(result.ssid ?? "<Hidden>")"
                    if let existing = networksByKey[key], existing.rssiValue >= result.rssiValue { return }
                    networksByKey[key] = result
                }
            } while Date() < deadline
        }
        return Array(networksByKey.values)
    }

    func securityTypeString(_ network: JWScanResult?) -> String {
        guard let network = network else { return "?" }
        if network.supportsSecurity(.none) { return "Open" }
        var parts: [String] = []
        if network.supportsSecurity(.WEP) { parts.append("WEP") }
        if network.supportsSecurity(.dynamicWEP) { parts.append("Dynamic WEP") }
        if network.supportsSecurity(.wpaPersonal) { parts.append("WPA (P)") }
        if network.supportsSecurity(.wpa2Personal) { parts.append("WPA2 (P)") }
        if network.supportsSecurity(.wpaEnterprise) { parts.append("WPA (E)") }
        if network.supportsSecurity(.wpa2Enterprise) { parts.append("WPA2 (E)") }
        if network.supportsSecurity(.unknown) { parts.append("Unknown") }
        return parts.isEmpty ? "?" : parts.joined(separator: " / ")
    }

    func sortNetworks(by key: String) {
        if sortOrder == key {
            sortAscending.toggle()
        } else {
            sortOrder = key
            sortAscending = true
        }

        let order: ComparisonResult = sortAscending ? .orderedAscending : .orderedDescending
        switch key {
        case "channelBand": networks.sort { String($0.channelBandRaw).localizedStandardCompare(String($1.channelBandRaw)) == order }
        case "channel": networks.sort { String($0.channelNumber).localizedStandardCompare(String($1.channelNumber)) == order }
        case "essid": networks.sort { ($0.ssid ?? "<Hidden>").localizedStandardCompare($1.ssid ?? "<Hidden>") == order }
        case "bssid": networks.sort { ($0.bssid ?? "").localizedStandardCompare($1.bssid ?? "") == order }
        case "enc": networks.sort { securityTypeString($0).localizedStandardCompare(securityTypeString($1)) == order }
        case "rssi": networks.sort { String($0.rssiValue).localizedStandardCompare(String($1.rssiValue)) == order }
        default: break
        }
    }

    var selectedNetworks: [JWScanResult] {
        networks.filter { selectedNetworkIDs.contains(networkID(for: $0)) }
    }

    func setSelection(_ ids: Set<String>) {
        selectedNetworkIDs = ids
        updateHeaderStats()
    }

    private func handleScanError() {
        isScanning = false
        updateHeaderStats(message: "Scan failed. Check permissions and try again.")
        DispatchQueue.main.async { [weak self] in
            self?.alertState?.show(title: "Scan Failed", message: "A network scan could not be completed at this time.")
        }
    }

    private func handleScanSuccess(_ theNetworks: [JWScanResult]?) {
        var newNetworks = theNetworks ?? []
        outerLoop: for existing in networks {
            for n in newNetworks where isNetworkEqual(existing, n) { continue outerLoop }
            newNetworks.append(existing)
        }
        isScanning = false
        networks = newNetworks
        syncSelection()
        updateHeaderStats()
    }

    private func isNetworkEqual(_ a: JWScanResult, _ b: JWScanResult) -> Bool {
        a.ssid == b.ssid && a.bssid == b.bssid && a.channelNumber == b.channelNumber && a.channelBandRaw == b.channelBandRaw
    }

    private func selectedBSSID() -> String? {
        selectedNetworks.first?.bssid
    }

    private func updateHeaderStats(message: String? = nil) {
        if let message = message {
            headerStatsText = message
            return
        }
        let selectionCount = selectedNetworkIDs.count
        if networks.isEmpty {
            headerStatsText = "No scan results yet"
        } else if selectionCount > 0 {
            headerStatsText = "\(networks.count) networks • \(selectionCount) selected"
        } else {
            headerStatsText = "\(networks.count) networks discovered"
        }
    }

    private func animateCopyFeedback() {
        copyFeedbackResetWorkItem?.cancel()
        copyButtonTitle = "Copied"
        let workItem = DispatchWorkItem { [weak self] in
            self?.copyButtonTitle = "Copy BSSID"
        }
        copyFeedbackResetWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.9, execute: workItem)
    }

    private func syncSelection() {
        let validIDs = Set(networks.map { networkID(for: $0) })
        selectedNetworkIDs = selectedNetworkIDs.intersection(validIDs)
    }

    fileprivate func networkID(for network: JWScanResult) -> String {
        network.bssid ?? "\(network.channelBandRaw)-\(network.channelNumber)-\(network.ssid ?? "<Hidden>")"
    }
}

struct JWListScreen: View {
    @ObservedObject var controller: JWListView

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .firstTextBaseline) {
                Text("Networks")
                    .font(.title2.weight(.semibold))
                Spacer()
                Text(controller.headerStatsText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(spacing: 0) {
                headerRow
                Divider()
                List(selection: Binding(
                    get: { controller.selectedNetworkIDs },
                    set: { controller.setSelection($0) }
                )) {
                    ForEach(controller.networks, id: \.self) { network in
                        NetworkRowView(
                            network: network,
                            securityText: controller.securityTypeString(network)
                        )
                        .tag(controller.networkID(for: network))
                    }
                }
                .listStyle(.plain)
            }

            HStack(spacing: 12) {
                Button("Deauth") { controller.disassociateButton(nil) }
                Button("Join") { controller.joinButton(nil) }
                    .disabled(controller.selectedNetworks.count != 1)
                Button("Scan") { controller.scanButton(nil) }
                    .keyboardShortcut("r", modifiers: [.command])
                Button(controller.copyButtonTitle) { controller.copyBSSID(nil) }
                    .disabled(controller.selectedNetworks.count != 1 || controller.selectedNetworks.first?.bssid == nil)
                Spacer()
                if controller.isScanning {
                    ProgressView()
                        .controlSize(.small)
                }
                Button("Monitor") { controller.jamButton(nil) }
                    .disabled(controller.selectedNetworks.isEmpty)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .sheet(isPresented: Binding(
            get: { controller.networkRequestingPassword != nil },
            set: { if !$0 { controller.dismissJoinPasswordSheet() } }
        )) {
            if let network = controller.networkRequestingPassword {
                JoinPasswordSheet(network: network, controller: controller)
            }
        }
    }

    private var headerRow: some View {
        HStack(spacing: 12) {
            headerButton("CH", key: "channel")
                .frame(width: 48, alignment: .leading)
            headerButton("ESSID", key: "essid")
                .frame(width: 180, alignment: .leading)
            headerButton("BSSID", key: "bssid")
                .frame(width: 150, alignment: .leading)
            headerButton("Security", key: "enc")
                .frame(maxWidth: .infinity, alignment: .leading)
            headerButton("RSSI", key: "rssi")
                .frame(width: 64, alignment: .trailing)
            headerButton("Band", key: "channelBand")
                .frame(width: 72, alignment: .leading)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
    }

    private func headerButton(_ title: String, key: String) -> some View {
        Button(title) {
            controller.sortNetworks(by: key)
        }
        .buttonStyle(.plain)
    }
}

private struct JoinPasswordSheet: View {
    let network: JWScanResult
    @ObservedObject var controller: JWListView
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Enter Password:")
                .font(.headline)
            TextField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Cancel") {
                    controller.dismissJoinPasswordSheet()
                }
                .keyboardShortcut(.cancelAction)
                Button("Try") {
                    controller.performJoin(to: network, password: password)
                    controller.clearJoinPasswordSheet()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 320)
    }
}

private struct NetworkRowView: View {
    let network: JWScanResult
    let securityText: String

    var body: some View {
        HStack(spacing: 12) {
            Text("\(network.channelNumber)")
                .frame(width: 48, alignment: .leading)
            Text(network.ssid ?? "<Hidden>")
                .frame(width: 180, alignment: .leading)
            Text(network.bssid ?? "")
                .font(.system(.body, design: .monospaced))
                .frame(width: 150, alignment: .leading)
            Text(securityText)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("\(network.rssiValue)")
                .frame(width: 64, alignment: .trailing)
            Text(channelBandLabel)
                .frame(width: 72, alignment: .leading)
        }
        .font(.system(size: 13))
    }

    private var channelBandLabel: String {
        switch network.channelBandRaw {
        case CWChannelBand.band2GHz.rawValue: return "2.4 GHz"
        case CWChannelBand.band5GHz.rawValue: return "5 GHz"
        default: return "?"
        }
    }
}

#if canImport(SwiftUI)
private struct JWListViewPreviewWrapper: View {
    @StateObject private var controller: JWListView = {
        let c = JWListView(navigation: nil)
        c.networks = JWPreviewFactory.sampleNetworks
        return c
    }()
    var body: some View { JWListScreen(controller: controller) }
}
struct JWListView_Previews: PreviewProvider {
    static var previews: some View {
        JWListViewPreviewWrapper()
            .frame(width: 1100, height: 720)
    }
}
#endif
