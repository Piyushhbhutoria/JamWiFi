import SwiftUI
import Combine

private let kUserScanOptions = "USER_SCAN_OPTIONS"

final class PreferencesStore: ObservableObject {
    @Published var mergeNetworks: Bool
    @Published var includePeerToPeer: Bool
    @Published var includeClosedNetworks: Bool
    @Published var selectedBSSType: Int
    @Published var selectedScanType: Int

    private let defaults = UserDefaults.standard
    private let bssTypes = ["IBSS", "BSS", "Both"]
    private let scanTypes = ["Active", "Passive", "Fast (Cached)"]

    init() {
        let prefs = UserDefaults.standard.dictionary(forKey: kUserScanOptions) ?? [:]
        mergeNetworks = prefs["SCAN_MERGE"] as? Bool ?? true
        includePeerToPeer = prefs["SCAN_P2P"] as? Bool ?? false
        includeClosedNetworks = prefs["SCAN_CLOSED_NETWORKS"] as? Bool ?? false
        selectedBSSType = max(0, (prefs["SCAN_BSS_TYPE"] as? Int ?? 3) - 1)
        selectedScanType = max(0, (prefs["SCAN_TYPE"] as? Int ?? 1) - 1)
    }

    var bssTypeOptions: [String] { bssTypes }
    var scanTypeOptions: [String] { scanTypes }

    func saveChanges() {
        defaults.set([
            "SCAN_MERGE": mergeNetworks,
            "SCAN_P2P": includePeerToPeer,
            "SCAN_CLOSED_NETWORKS": includeClosedNetworks,
            "SCAN_BSS_TYPE": selectedBSSType + 1,
            "SCAN_TYPE": selectedScanType + 1
        ], forKey: kUserScanOptions)
    }

    func discardChanges() {
        let prefs = defaults.dictionary(forKey: kUserScanOptions) ?? [:]
        mergeNetworks = prefs["SCAN_MERGE"] as? Bool ?? true
        includePeerToPeer = prefs["SCAN_P2P"] as? Bool ?? false
        includeClosedNetworks = prefs["SCAN_CLOSED_NETWORKS"] as? Bool ?? false
        selectedBSSType = max(0, (prefs["SCAN_BSS_TYPE"] as? Int ?? 3) - 1)
        selectedScanType = max(0, (prefs["SCAN_TYPE"] as? Int ?? 1) - 1)
    }
}

struct JWPreferencesScreen: View {
    @ObservedObject var store: PreferencesStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Scanning")
                    .font(.title3.weight(.semibold))
                Text("Configure how JamWiFi discovers nearby access points.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Form {
                Toggle("Merge networks with same SSIDs and different BSSIDs", isOn: $store.mergeNetworks)
                Toggle("Include Peer-to-Peer (awdl0) networks", isOn: $store.includePeerToPeer)
                Toggle("Include closed networks", isOn: $store.includeClosedNetworks)

                Picker("BSS Type", selection: $store.selectedBSSType) {
                    ForEach(Array(store.bssTypeOptions.enumerated()), id: \.offset) { index, title in
                        Text(title).tag(index)
                    }
                }

                Picker("Scan Type", selection: $store.selectedScanType) {
                    ForEach(Array(store.scanTypeOptions.enumerated()), id: \.offset) { index, title in
                        Text(title).tag(index)
                    }
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Discard") {
                    store.discardChanges()
                }
                Button("Save") {
                    store.saveChanges()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

#if canImport(SwiftUI)
struct JWPreferences_Previews: PreviewProvider {
    static var previews: some View {
        JWPreferencesScreen(store: PreferencesStore())
            .frame(width: 520, height: 280)
    }
}
#endif
