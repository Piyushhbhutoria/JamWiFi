import Foundation
import CoreWLAN

/// Called when the binary is launched with `--scan-mode`.
/// Runs as the console user (dropped from root by the parent via fork+setuid+execv)
/// so CoreWLAN returns real SSID and BSSID values.
@objc class JWScanModeRunner: NSObject {
    @objc static func run() {
        guard let iface = CWWiFiClient.shared().interface() else {
            print("[]")
            return
        }

        // Scan on a background thread while spinning the run loop so XPC/CoreWLAN
        // callbacks can be delivered even without a full Cocoa app running.
        var found: Set<CWNetwork> = []
        let sem = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            found = (try? iface.scanForNetworks(withSSID: nil)) ?? []
            sem.signal()
        }
        let deadline = Date(timeIntervalSinceNow: 8.0)
        while sem.wait(timeout: .now()) == .timedOut {
            if Date() > deadline { break }
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        }

        // CWSecurity.unknown has rawValue = -1, so we enumerate only the cases
        // we care about and store them as an array of raw values.
        let securities: [CWSecurity] = [
            .none, .WEP, .dynamicWEP,
            .wpaPersonal, .wpa2Personal, .personal,
            .wpaEnterprise, .wpa2Enterprise, .enterprise,
            .unknown
        ]

        var results: [[String: Any]] = []
        for network in found {
            var entry: [String: Any] = [
                "rssi":          network.rssiValue,
                "channelNumber": network.wlanChannel?.channelNumber ?? 0,
                "channelBand":   network.wlanChannel?.channelBand.rawValue ?? 0
            ]
            if let ssid  = network.ssid  { entry["ssid"]  = ssid  }
            if let bssid = network.bssid { entry["bssid"] = bssid }

            let supportedRawValues = securities
                .filter { network.supportsSecurity($0) }
                .map    { $0.rawValue }
            entry["security"] = supportedRawValues
            results.append(entry)
        }

        if let data = try? JSONSerialization.data(withJSONObject: results),
           let str  = String(data: data, encoding: .utf8) {
            print(str)
        } else {
            print("[]")
        }
    }
}
