import Foundation
import CoreWLAN
import AppKit
import SwiftUI
import Combine

final class JWTrafficGatherer: NSObject, ObservableObject, ANWiFiSnifferDelegate {
    weak var navigation: AppNavigation?
    weak var alertState: AppAlertState?
    var sniffer: ANWiFiSniffer?
    var networks: [JWScanResult] = []
    var channels: [CWChannel] = []
    var channelIndex = 0
    var hopTimer: Timer?

    @Published var allClients: [JWClient] = []
    @Published var headerStatsText = "Listening for traffic"

    private var sortAscending = true
    private var sortOrder = ""

    init(navigation: AppNavigation?, sniffer aSniffer: ANWiFiSniffer?, networks theNetworks: [JWScanResult]?, alertState: AppAlertState? = nil) {
        self.navigation = navigation
        self.alertState = alertState ?? navigation?.alertState
        if let theNetworks = theNetworks { networks = theNetworks }
        sniffer = aSniffer
        super.init()

        var discoveredChannels: [CWChannel] = []
        for net in networks {
            if let ch = net.wlanChannel,
               !discoveredChannels.contains(where: { $0.channelNumber == ch.channelNumber && $0.channelBand == ch.channelBand }) {
                discoveredChannels.append(ch)
            }
        }
        channels = discoveredChannels
        channelIndex = -1
        hopChannel()
        if aSniffer != nil {
            hopTimer = Timer.scheduledTimer(timeInterval: 0.25, target: self, selector: #selector(hopChannel), userInfo: nil, repeats: true)
        }
        sniffer?.delegate = self
        sniffer?.start()
    }

    func backButton(_ sender: Any?) {
        hopTimer?.invalidate()
        hopTimer = nil
        sniffer?.stop()
        sniffer?.delegate = nil
        sniffer = nil
        navigation?.popToRoot()
    }

    func continueButton(_ sender: Any?) {
        guard !allClients.isEmpty else { return }
        hopTimer?.invalidate()
        hopTimer = nil
        let killer = JWClientKiller(navigation: navigation, sniffer: sniffer, networks: networks, clients: allClients)
        navigation?.push(.killer(killer))
    }

    func toggleClient(_ client: JWClient, enabled: Bool) {
        client.enabled = enabled
        objectWillChange.send()
    }

    func sortClients(by key: String) {
        sortClients(by: key, toggleDirection: true)
    }

    private func sortClients(by key: String, toggleDirection: Bool) {
        if sortOrder == key, toggleDirection {
            sortAscending.toggle()
        } else {
            sortOrder = key
            if toggleDirection {
                sortAscending = true
            }
        }

        let order: ComparisonResult = sortAscending ? .orderedAscending : .orderedDescending
        switch key {
        case "enabled": allClients.sort { $0.enabled.description.localizedStandardCompare($1.enabled.description) == order }
        case "device": allClients.sort { MACToString($0.macAddress).localizedStandardCompare(MACToString($1.macAddress)) == order }
        case "bssid": allClients.sort { MACToString($0.bssid).localizedStandardCompare(MACToString($1.bssid)) == order }
        case "count": allClients.sort { String($0.packetCount).localizedStandardCompare(String($1.packetCount)) == order }
        case "rssi": allClients.sort { String($0.rssi).localizedStandardCompare(String($1.rssi)) == order }
        default: break
        }
    }

    func includesBSSID(_ bssid: UnsafePointer<UInt8>?) -> Bool {
        networks.containsBSSID(bssid)
    }

    @objc func hopChannel() {
        guard !channels.isEmpty else { return }
        channelIndex += 1
        if channelIndex >= channels.count {
            channelIndex = 0
        }
        sniffer?.setChannel(channels[channelIndex])
    }

    func wifiSnifferFailed(toOpenInterface sniffer: ANWiFiSniffer?) {
        DispatchQueue.main.async { [weak self] in
            self?.alertState?.show(title: "Interface Error", message: "Failed to open sniffer interface.")
        }
    }

    func wifiSniffer(_ sniffer: ANWiFiSniffer?, failedWithError error: Error?) {
        DispatchQueue.main.async { [weak self] in
            self?.alertState?.show(title: "Sniff Error", message: "Got a sniff error. Please try again.")
        }
    }

    func wifiSniffer(_ sniffer: ANWiFiSniffer?, gotPacket packet: AN80211Packet?) {
        var hasClient = false
        var client = [CUnsignedChar](repeating: 0, count: 6)
        var bssid = [CUnsignedChar](repeating: 0, count: 6)
        if packet?.dataFCS() != packet?.calculateFCS() { return }

        if packet?.macHeader().pointee.frame_control.from_ds == 0 && packet?.macHeader().pointee.frame_control.to_ds == 1 {
            bssid = withUnsafeBytes(of: packet?.macHeader().pointee.mac1) { Array($0.bindMemory(to: CUnsignedChar.self)) }
            if !includesBSSID(bssid) { return }
            client = withUnsafeBytes(of: packet?.macHeader().pointee.mac2) { Array($0.bindMemory(to: CUnsignedChar.self)) }
            hasClient = true
        } else if packet?.macHeader().pointee.frame_control.from_ds == 0 && packet?.macHeader().pointee.frame_control.to_ds == 0 {
            bssid = withUnsafeBytes(of: packet?.macHeader().pointee.mac3) { Array($0.bindMemory(to: CUnsignedChar.self)) }
            if !includesBSSID(bssid) { return }
            if memcmp(withUnsafeBytes(of: packet?.macHeader().pointee.mac2) { $0.baseAddress! }, withUnsafeBytes(of: packet?.macHeader().pointee.mac3) { $0.baseAddress! }, 6) != 0 {
                client = withUnsafeBytes(of: packet?.macHeader().pointee.mac2) { Array($0.bindMemory(to: CUnsignedChar.self)) }
                hasClient = true
            }
        } else if packet?.macHeader().pointee.frame_control.from_ds == 1 && packet?.macHeader().pointee.frame_control.to_ds == 0 {
            bssid = withUnsafeBytes(of: packet?.macHeader().pointee.mac2) { Array($0.bindMemory(to: CUnsignedChar.self)) }
            if !includesBSSID(bssid) { return }
            client = withUnsafeBytes(of: packet?.macHeader().pointee.mac1) { Array($0.bindMemory(to: CUnsignedChar.self)) }
            hasClient = true
        }

        if client[0] == 0x33 && client[1] == 0x33 { hasClient = false }
        if client[0] == 0x01 && client[1] == 0x00 { hasClient = false }
        if client[0] == 0xff && client[1] == 0xff { hasClient = false }
        if client[0] == 0x03 && client[5] == 0x01 { hasClient = false }

        if hasClient {
            DispatchQueue.main.async {
                let clientObj = JWClient(mac: client, bssid: bssid)
                if !self.allClients.contains(clientObj) {
                    self.allClients.append(clientObj)
                } else if let index = self.allClients.firstIndex(of: clientObj) {
                    let origClient = self.allClients[index]
                    origClient.packetCount += 1
                    origClient.rssi = Float(packet!.rssi)
                }
                if self.sortOrder.isEmpty {
                    self.sortOrder = "device"
                    self.sortAscending = true
                }
                self.sortClients(by: self.sortOrder, toggleDirection: false)
                self.headerStatsText = "\(self.allClients.count) clients observed • \(self.networks.count) APs selected"
            }
        }
    }

    fileprivate func clientID(for client: JWClient) -> String {
        "\(MACToString(client.macAddress))-\(MACToString(client.bssid))"
    }
}

struct JWTrafficGathererScreen: View {
    @ObservedObject var controller: JWTrafficGatherer

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Clients")
                    .font(.title2.weight(.semibold))
                Spacer()
                Text(controller.headerStatsText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(spacing: 0) {
                headerRow
                Divider()
                List {
                    ForEach(controller.allClients, id: \.self) { client in
                        HStack(spacing: 12) {
                            Toggle("", isOn: Binding(
                                get: { client.enabled },
                                set: { controller.toggleClient(client, enabled: $0) }
                            ))
                            .labelsHidden()
                            .frame(width: 30, alignment: .leading)
                            Text(MACToString(client.macAddress))
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 160, alignment: .leading)
                            Text(MACToString(client.bssid))
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 160, alignment: .leading)
                            Text("\(client.packetCount)")
                                .frame(width: 80, alignment: .trailing)
                            Text(String(format: "%.0f", client.rssi))
                                .frame(width: 70, alignment: .trailing)
                        }
                        .font(.system(size: 13))
                    }
                }
                .listStyle(.plain)
            }

            HStack {
                Button("Back") { controller.backButton(nil) }
                Spacer()
                Button("Jam") { controller.continueButton(nil) }
                    .disabled(controller.allClients.isEmpty)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var headerRow: some View {
        HStack(spacing: 12) {
            headerButton("Jam", key: "enabled")
                .frame(width: 30, alignment: .leading)
            headerButton("Device", key: "device")
                .frame(width: 160, alignment: .leading)
            headerButton("BSSID", key: "bssid")
                .frame(width: 160, alignment: .leading)
            headerButton("Packets", key: "count")
                .frame(width: 80, alignment: .trailing)
            headerButton("RSSI", key: "rssi")
                .frame(width: 70, alignment: .trailing)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
    }

    private func headerButton(_ title: String, key: String) -> some View {
        Button(title) {
            controller.sortClients(by: key)
        }
        .buttonStyle(.plain)
    }
}

#if canImport(SwiftUI)
private struct JWTrafficGathererPreviewWrapper: View {
    @StateObject private var controller: JWTrafficGatherer = {
        let c = JWTrafficGatherer(navigation: nil, sniffer: nil, networks: JWPreviewFactory.sampleNetworks)
        c.allClients = JWPreviewFactory.sampleClients
        return c
    }()
    var body: some View { JWTrafficGathererScreen(controller: controller) }
}
struct JWTrafficGatherer_Previews: PreviewProvider {
    static var previews: some View {
        JWTrafficGathererPreviewWrapper()
            .frame(width: 1100, height: 720)
    }
}
#endif
