# JamWiFi

Continuation of [unixpickle/JamWiFi](https://github.com/unixpickle/JamWiFi). Swift rewrite with a native macOS UI.

**Version:** 2.0.0  
**Platform:** macOS 26 (Tahoe) or later (Xcode project)

---

## What it does

- Scan nearby wireless networks (CoreWLAN).
- List clients on selected network(s) (raw 802.11 via libpcap).
- Disconnect chosen clients by sending disassociation frames (optionally from all visible APs).
- Join by BSSID, settings (hidden networks, scan options), column sorting.
- SwiftUI-only UI with Settings and native menu.

## Build

1. Open `JamWiFi.xcodeproj` in Xcode.
2. Build and run (⌘R).

No pre-built binaries are provided; build from source. Requires macOS 26 (Tahoe) or later.

## Tech

- **UI:** SwiftUI only (no Objective-C UI, no XIBs). Entry point is Swift `@main`; menu and preferences use SwiftUI Commands and Settings.
- **Wireless:** CoreWLAN (scan/channel), libpcap + Apple80211 (raw frames), Obj-C beacon/packet code in `Wireless/`.

---

## How it works

CoreWLAN is used for channel hopping and scanning. libpcap gives a raw packet interface for 802.11 frames. Clients are inferred from MAC source/destination in frames. Disassociation frames are sent repeatedly to chosen clients so they drop and stay off the AP; for multi-AP networks, frames are sent from every AP so clients can’t just roam to another AP.

## Caveats

Networks with multiple APs (or multiple SSIDs in range) may allow clients to reassociate elsewhere. Sending disassociation from every visible AP to every target client reduces that but adds traffic.

## Disclaimer

For experimentation and learning only. You are responsible for your use of this tool. Do not use it to disrupt others’ networks.
