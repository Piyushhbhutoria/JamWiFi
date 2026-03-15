import Foundation

func MACToString(_ mac: UnsafePointer<UInt8>?) -> String {
    guard let mac = mac else { return "" }
    return String(format: "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func copyMAC(_ macString: String?, _ mac: UnsafeMutablePointer<UInt8>) -> Bool {
    guard let macString = macString else { return false }
    let components = macString.split(separator: ":", omittingEmptySubsequences: false)
    for (i, part) in components.prefix(6).enumerated() {
        mac[i] = UInt8(part, radix: 16) ?? 0
    }
    return true
}
