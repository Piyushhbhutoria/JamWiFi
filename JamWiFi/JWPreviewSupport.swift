import Foundation

#if canImport(SwiftUI)
import SwiftUI

// Raw values only — no CoreWLAN import so preview process doesn't touch WiFi stack.
private let band2GHz = 1
private let band5GHz = 2
private let securityNone = 0
private let securityWPA2Personal = 4

enum JWPreviewFactory {
    static let sampleNetworks: [JWScanResult] = [
        JWScanResult(
            ssid: "Studio",
            bssid: "34:12:98:ab:cd:01",
            rssiValue: -42,
            channelNumber: 1,
            channelBandRaw: band2GHz,
            wlanChannel: nil,
            supportedSecurityRawValues: Set([securityWPA2Personal])
        ),
        JWScanResult(
            ssid: "Office-5G",
            bssid: "34:12:98:ab:cd:02",
            rssiValue: -57,
            channelNumber: 36,
            channelBandRaw: band5GHz,
            wlanChannel: nil,
            supportedSecurityRawValues: Set([securityWPA2Personal])
        ),
        JWScanResult(
            ssid: "Guest",
            bssid: "34:12:98:ab:cd:03",
            rssiValue: -71,
            channelNumber: 11,
            channelBandRaw: band2GHz,
            wlanChannel: nil,
            supportedSecurityRawValues: Set([securityNone])
        )
    ]

    static let sampleClients: [JWClient] = [
        makeClient(mac: [0x10, 0x22, 0x33, 0x44, 0x55, 0x66],
                  bssid: [0x34, 0x12, 0x98, 0xab, 0xcd, 0x01],
                  packetCount: 128,
                  deauthsSent: 14,
                  rssi: -48,
                  enabled: true),
        makeClient(mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
                  bssid: [0x34, 0x12, 0x98, 0xab, 0xcd, 0x02],
                  packetCount: 42,
                  deauthsSent: 3,
                  rssi: -63,
                  enabled: false)
    ]

    private static func makeClient(mac: [CUnsignedChar],
                                   bssid: [CUnsignedChar],
                                   packetCount: Int,
                                   deauthsSent: Int,
                                   rssi: Float,
                                   enabled: Bool) -> JWClient {
        let client = JWClient(mac: mac, bssid: bssid)
        client.packetCount = packetCount
        client.deauthsSent = deauthsSent
        client.rssi = rssi
        client.enabled = enabled
        return client
    }
}
#endif
