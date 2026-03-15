import Foundation
import CoreWLAN

private let checkedSecurities: [CWSecurity] = [
    .none, .WEP, .dynamicWEP, .wpaPersonal, .wpa2Personal, .personal,
    .wpaEnterprise, .wpa2Enterprise, .enterprise, .unknown
]

/// Lightweight network model built from JSON emitted by the scan subprocess.
/// Replaces CWNetwork throughout the app so we can obtain real SSID/BSSID values
/// even though the main process runs as root.
class JWScanResult: NSObject {
    let ssid: String?
    let bssid: String?
    let rssiValue: Int
    let channelNumber: Int
    let channelBandRaw: Int
    /// Resolved once at parse time from the interface's supported channels.
    let wlanChannel: CWChannel?
    private let supportedSecurityRawValues: Set<Int>

    init(ssid: String?, bssid: String?, rssiValue: Int,
         channelNumber: Int, channelBandRaw: Int,
         wlanChannel: CWChannel?, supportedSecurityRawValues: Set<Int>) {
        self.ssid = ssid
        self.bssid = bssid
        self.rssiValue = rssiValue
        self.channelNumber = channelNumber
        self.channelBandRaw = channelBandRaw
        self.wlanChannel = wlanChannel
        self.supportedSecurityRawValues = supportedSecurityRawValues
    }

    func supportsSecurity(_ security: CWSecurity) -> Bool {
        return supportedSecurityRawValues.contains(security.rawValue)
    }

    func withResolvedIdentity(ssid: String?, bssid: String?) -> JWScanResult {
        JWScanResult(
            ssid: ssid ?? self.ssid,
            bssid: bssid ?? self.bssid,
            rssiValue: rssiValue,
            channelNumber: channelNumber,
            channelBandRaw: channelBandRaw,
            wlanChannel: wlanChannel,
            supportedSecurityRawValues: supportedSecurityRawValues
        )
    }

    /// Build directly from a CWNetwork (returned by Apple80211Scan, which populates
    /// SSID and BSSID without Location Services restrictions).
    static func from(cwNetwork n: CWNetwork) -> JWScanResult {
        let ch   = n.wlanChannel?.channelNumber ?? 0
        let band = n.wlanChannel?.channelBand.rawValue ?? 0
        let secRaw = Set(checkedSecurities.filter { n.supportsSecurity($0) }.map { $0.rawValue })
        return JWScanResult(
            ssid:                       resolvedSSID(from: n),
            bssid:                      resolvedBSSID(from: n),
            rssiValue:                  n.rssiValue,
            channelNumber:              ch,
            channelBandRaw:             band,
            wlanChannel:                n.wlanChannel,
            supportedSecurityRawValues: secRaw
        )
    }

    static func from(beaconPacket packet: AN80211Packet, supportedChannels: Set<CWChannel>) -> JWScanResult? {
        guard let beacon = ANBeaconFrame(packet: packet) else { return nil }

        let channelNumber = Int(beacon.channel())
        guard channelNumber > 0 else { return nil }

        let channel = supportedChannels.first { $0.channelNumber == channelNumber }
        let channelBandRaw = channel?.channelBand.rawValue ?? inferredBandRaw(for: channelNumber)

        return JWScanResult(
            ssid: normalizedSSID(beacon.essid()),
            bssid: bssidString(from: packet),
            rssiValue: Int(packet.rssi),
            channelNumber: channelNumber,
            channelBandRaw: channelBandRaw,
            wlanChannel: channel,
            supportedSecurityRawValues: securityRawValues(from: packet, beacon: beacon)
        )
    }

    static func from(dict: [String: Any]) -> JWScanResult? {
        guard let ch   = dict["channelNumber"] as? Int,
              let band = dict["channelBand"]   as? Int else { return nil }

        // Look up a real CWChannel once so channel-hop comparisons are stable.
        let channel = CWWiFiClient.shared().interface()?.supportedWLANChannels()?.first {
            $0.channelNumber == ch && $0.channelBand.rawValue == band
        }

        let secRaw = Set((dict["security"] as? [Int]) ?? [])
        return JWScanResult(
            ssid:                     dict["ssid"]  as? String,
            bssid:                    dict["bssid"] as? String,
            rssiValue:                dict["rssi"]  as? Int ?? 0,
            channelNumber:            ch,
            channelBandRaw:           band,
            wlanChannel:              channel,
            supportedSecurityRawValues: secRaw
        )
    }

    private static func resolvedSSID(from network: CWNetwork) -> String? {
        if let ssid = normalizedSSID(network.ssid) {
            return ssid
        }
        if let scanRecord = dynamicValue(named: "scanRecord", on: network) as? [String: Any],
           let ssid = normalizedSSID(scanRecord["SSID_STR"] as? String) {
            return ssid
        }
        if let rawScanResult = dynamicObject(named: "coreWiFiScanResult", on: network),
           let ssid = normalizedSSID(dynamicValue(named: "networkName", on: rawScanResult) as? String) {
            return ssid
        }
        return nil
    }

    private static func resolvedBSSID(from network: CWNetwork) -> String? {
        if let bssid = normalizedBSSID(network.bssid) {
            return bssid
        }
        if let rawScanResult = dynamicObject(named: "coreWiFiScanResult", on: network),
           let bssid = normalizedBSSID(dynamicValue(named: "BSSID", on: rawScanResult) as? String) {
            return bssid
        }
        return nil
    }

    private static func normalizedSSID(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return trimmed
    }

    private static func normalizedBSSID(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return trimmed.lowercased()
    }

    private static func dynamicObject(named selectorName: String, on object: NSObject) -> NSObject? {
        dynamicValue(named: selectorName, on: object) as? NSObject
    }

    private static func dynamicValue(named selectorName: String, on object: NSObject) -> Any? {
        let selector = NSSelectorFromString(selectorName)
        guard object.responds(to: selector),
              let unmanaged = object.perform(selector) else { return nil }
        return unmanaged.takeUnretainedValue()
    }

    private static func inferredBandRaw(for channelNumber: Int) -> Int {
        if (1...14).contains(channelNumber) {
            return CWChannelBand.band2GHz.rawValue
        }
        return CWChannelBand.band5GHz.rawValue
    }

    private static func bssidString(from packet: AN80211Packet) -> String? {
        let header = packet.macHeader().pointee
        return withUnsafeBytes(of: header.mac3) { rawBuffer in
            guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                return nil
            }
            return normalizedBSSID(MACToString(baseAddress))
        }
    }

    private static func securityRawValues(from packet: AN80211Packet, beacon: ANBeaconFrame) -> Set<Int> {
        var values = Set<Int>()

        if beacon.beaconPart(withID: 48) != nil {
            values.insert(CWSecurity.wpa2Personal.rawValue)
        }
        if let vendorPart = beacon.beaconPart(withID: 221),
           isWPAInformationElement(vendorPart.data) {
            values.insert(CWSecurity.wpaPersonal.rawValue)
        }

        guard values.isEmpty else { return values }

        let bodyLength = Int(packet.bodyLength())
        guard bodyLength >= 12 else { return [CWSecurity.unknown.rawValue] }

        let body = Data(bytes: packet.bodyData(), count: bodyLength)
        let capabilities = UInt16(body[10]) | (UInt16(body[11]) << 8)
        if capabilities & 0x0010 == 0 {
            values.insert(CWSecurity.none.rawValue)
        } else {
            values.insert(CWSecurity.unknown.rawValue)
        }
        return values
    }

    private static func isWPAInformationElement(_ data: Data) -> Bool {
        let signature: [UInt8] = [0x00, 0x50, 0xF2, 0x01]
        guard data.count >= signature.count else { return false }
        return data.prefix(signature.count).elementsEqual(signature)
    }
}
