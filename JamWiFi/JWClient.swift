


import Foundation

class JWClient: NSObject {
	var packetCount = 0
	var deauthsSent = 0
	private(set) var macAddress: [CUnsignedChar] = []
	private(set) var bssid: [CUnsignedChar] = []
	var rssi: Float = 0.0
	var enabled = false
	
	init(mac: UnsafePointer<CUnsignedChar>?, bssid aBSSID: UnsafePointer<CUnsignedChar>?) {
		super.init()
		macAddress = [CUnsignedChar](repeating: 0, count: 6)
		bssid = [CUnsignedChar](repeating: 0, count: 6)
		packetCount = 0
		if let mac = mac { memcpy(&macAddress, mac, 6) }
		if let aBSSID = aBSSID { memcpy(&bssid, aBSSID, 6) }
		enabled = true
	}

	/// Preview/sample data only; copies from arrays so no pointer lifetime issues.
	init(mac: [CUnsignedChar], bssid aBSSID: [CUnsignedChar]) {
		super.init()
		let m = Array(mac.prefix(6))
		let b = Array(aBSSID.prefix(6))
		macAddress = m + [CUnsignedChar](repeating: 0, count: max(0, 6 - m.count))
		bssid = b + [CUnsignedChar](repeating: 0, count: max(0, 6 - b.count))
		packetCount = 0
		enabled = true
	}
	
	override func isEqual(_ object: Any?) -> Bool {
		guard let client = object as? JWClient else { return false }
		guard client.bssid.count >= 6, bssid.count >= 6, client.macAddress.count >= 6, macAddress.count >= 6 else { return false }
		return client.bssid.prefix(6).elementsEqual(bssid.prefix(6)) && client.macAddress.prefix(6).elementsEqual(macAddress.prefix(6))
	}

	override var hash: Int {
		var hasher = Hasher()
		hasher.combine(Array(macAddress.prefix(6)))
		hasher.combine(Array(bssid.prefix(6)))
		return hasher.finalize()
	}
}
