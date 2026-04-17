import SwiftUI
import Combine

/// NDN BLE test UI.
///
/// Scans for NDN BLE peripherals, connects, sends Interests, and displays
/// received Data packets.
struct ContentView: View {
    @StateObject private var bleClient = BleClient()
    @State private var framingMode: NdnBleProtocol.FramingMode = .ndnlpv2
    @State private var cancellables = Set<AnyCancellable>()
    @State private var reassembler = NdnBleProtocol.NdntsReassembler()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("NDN BLE Test")
                .font(.title)
                .bold()

            // Framing mode picker.
            Picker("Framing", selection: $framingMode) {
                ForEach(NdnBleProtocol.FramingMode.allCases, id: \.self) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            // Control buttons.
            HStack {
                Button("Scan") { onScan() }
                    .disabled(bleClient.state == .scanning || bleClient.state == .connected)
                Button("Send Interest") { onSendInterest() }
                    .disabled(bleClient.state != .connected)
                Button("Disconnect") { bleClient.disconnect() }
                    .disabled(bleClient.state != .connected)
            }

            // Status.
            Text("Status: \(stateLabel)")
                .font(.headline)

            // Device list (during scan).
            if bleClient.state == .scanning && !bleClient.scannedDevices.isEmpty {
                Text("Tap a device to connect:")
                    .font(.subheadline)
                List(bleClient.scannedDevices) { device in
                    Button(action: { bleClient.connect(device: device) }) {
                        Text("\(device.name) [\(device.id.uuidString.prefix(8))...]")
                    }
                }
                .frame(maxHeight: 150)
            }

            // Log output.
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading) {
                        ForEach(Array(bleClient.log.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .id(index)
                        }
                    }
                }
                .onChange(of: bleClient.log.count) { _, newCount in
                    proxy.scrollTo(newCount - 1, anchor: .bottom)
                }
            }
        }
        .padding()
        .onAppear {
            bleClient.rxData
                .receive(on: DispatchQueue.main)
                .sink { data in handleRxData(data) }
                .store(in: &cancellables)
        }
    }

    // MARK: - State label

    private var stateLabel: String {
        switch bleClient.state {
        case .idle: return "idle"
        case .scanning: return "scanning ..."
        case .connecting: return "connecting ..."
        case .connected: return "connected"
        case .disconnected: return "disconnected"
        }
    }

    // MARK: - Actions

    private func onScan() {
        bleClient.startScan()
        // Auto-stop after 10 seconds.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
            bleClient.stopScan()
        }
    }

    private func onSendInterest() {
        let name = framingMode == .ndntsBle ? "/ndn/ble/esp32" : "/ndn/ble/test"
        let nonce = UInt32.random(in: 0...UInt32.max)
        let interestWire = NdnCodec.encodeInterest(name: name, nonce: nonce)

        bleClient.appendLog("Sending Interest: \(name) (\(interestWire.count) bytes)")

        switch framingMode {
        case .ndnlpv2:
            let lpWire = NdnCodec.wrapLpPacket(interestWire)
            bleClient.appendLog("  NDNLPv2 envelope: \(lpWire.count) bytes")
            let ok = bleClient.writeCs(lpWire)
            bleClient.appendLog(ok ? "  Written to CS" : "  Write FAILED")

        case .ndntsBle:
            let fragments = NdnBleProtocol.ndntsFrame(packet: interestWire, maxPayload: 244)
            bleClient.appendLog("  NDNts framing: \(fragments.count) fragment(s)")
            for (i, frag) in fragments.enumerated() {
                let ok = bleClient.writeCs(frag)
                bleClient.appendLog("    frag[\(i)]: \(frag.count) bytes -- \(ok ? "OK" : "FAILED")")
            }
        }

        reassembler.reset()
    }

    private func handleRxData(_ raw: Data) {
        bleClient.appendLog("RX: \(raw.count) bytes")

        switch framingMode {
        case .ndnlpv2:
            guard let inner = NdnCodec.unwrapLpPacket(raw) else {
                bleClient.appendLog("  Failed to unwrap LpPacket")
                return
            }
            decodeAndDisplay(inner)

        case .ndntsBle:
            if let complete = reassembler.feed(raw) {
                decodeAndDisplay(complete)
            } else {
                bleClient.appendLog("  Fragment buffered, waiting for more ...")
            }
        }
    }

    private func decodeAndDisplay(_ wire: Data) {
        guard let (name, content) = NdnCodec.decodeData(wire) else {
            bleClient.appendLog("  Failed to decode Data packet (\(wire.count) bytes)")
            return
        }
        let text = String(data: content, encoding: .utf8) ?? "<binary>"
        bleClient.appendLog("Data received!")
        bleClient.appendLog("  Name: \(name)")
        bleClient.appendLog("  Content: \(text)")
    }
}
