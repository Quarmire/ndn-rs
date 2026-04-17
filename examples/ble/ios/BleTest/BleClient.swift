import CoreBluetooth
import Combine
import Foundation

/// BLE GATT central client for NDN-over-BLE testing.
///
/// Scans for the NDN BLE service, connects, and provides read/write access
/// to the CS (write) and SC (notify) characteristics.
class BleClient: NSObject, ObservableObject {
    enum State: Equatable {
        case idle
        case scanning
        case connecting
        case connected
        case disconnected
    }

    struct ScannedDevice: Identifiable {
        let id: UUID
        let peripheral: CBPeripheral
        let name: String
    }

    @Published var state: State = .idle
    @Published var scannedDevices: [ScannedDevice] = []
    @Published var log: [String] = []

    let rxData = PassthroughSubject<Data, Never>()

    private var centralManager: CBCentralManager!
    private var connectedPeripheral: CBPeripheral?
    private var csCharacteristic: CBCharacteristic?
    private var scCharacteristic: CBCharacteristic?

    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    func appendLog(_ msg: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        DispatchQueue.main.async {
            self.log.append("[\(ts)] \(msg)")
        }
    }

    // MARK: - Scanning

    func startScan() {
        scannedDevices = []
        state = .scanning
        appendLog("Scanning for NDN BLE peripherals ...")
        centralManager.scanForPeripherals(
            withServices: [NdnBleProtocol.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    func stopScan() {
        centralManager.stopScan()
        if state == .scanning { state = .idle }
    }

    // MARK: - Connection

    func connect(device: ScannedDevice) {
        stopScan()
        state = .connecting
        appendLog("Connecting to \(device.name) ...")
        connectedPeripheral = device.peripheral
        centralManager.connect(device.peripheral, options: nil)
    }

    func disconnect() {
        if let p = connectedPeripheral {
            centralManager.cancelPeripheralConnection(p)
        }
        connectedPeripheral = nil
        csCharacteristic = nil
        scCharacteristic = nil
        state = .disconnected
        appendLog("Disconnected")
    }

    // MARK: - Write

    func writeCs(_ data: Data) -> Bool {
        guard let cs = csCharacteristic, let p = connectedPeripheral else { return false }
        p.writeValue(data, for: cs, type: .withoutResponse)
        return true
    }
}

// MARK: - CBCentralManagerDelegate

extension BleClient: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            appendLog("Bluetooth powered on")
        case .poweredOff:
            appendLog("Bluetooth powered off")
        case .unauthorized:
            appendLog("Bluetooth unauthorized")
        default:
            appendLog("Bluetooth state: \(central.state.rawValue)")
        }
    }

    func centralManager(_ central: CBCentralManager,
                         didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any],
                         rssi RSSI: NSNumber) {
        let name = peripheral.name ?? advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? "unknown"
        if !scannedDevices.contains(where: { $0.peripheral.identifier == peripheral.identifier }) {
            let device = ScannedDevice(id: peripheral.identifier, peripheral: peripheral, name: name)
            DispatchQueue.main.async {
                self.scannedDevices.append(device)
            }
            appendLog("Found: \(name) [\(peripheral.identifier)]")
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        appendLog("Connected, discovering services ...")
        peripheral.delegate = self
        peripheral.discoverServices([NdnBleProtocol.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager,
                         didFailToConnect peripheral: CBPeripheral,
                         error: Error?) {
        state = .disconnected
        appendLog("Connection failed: \(error?.localizedDescription ?? "unknown")")
    }

    func centralManager(_ central: CBCentralManager,
                         didDisconnectPeripheral peripheral: CBPeripheral,
                         error: Error?) {
        state = .disconnected
        appendLog("Disconnected: \(error?.localizedDescription ?? "clean")")
    }
}

// MARK: - CBPeripheralDelegate

extension BleClient: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil else {
            appendLog("Service discovery error: \(error!)")
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == NdnBleProtocol.serviceUUID }) else {
            appendLog("NDN BLE service not found!")
            return
        }
        peripheral.discoverCharacteristics(
            [NdnBleProtocol.csCharUUID, NdnBleProtocol.scCharUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral,
                     didDiscoverCharacteristicsFor service: CBService,
                     error: Error?) {
        guard error == nil else {
            appendLog("Characteristic discovery error: \(error!)")
            return
        }
        for char in service.characteristics ?? [] {
            if char.uuid == NdnBleProtocol.csCharUUID {
                csCharacteristic = char
            } else if char.uuid == NdnBleProtocol.scCharUUID {
                scCharacteristic = char
                peripheral.setNotifyValue(true, for: char)
            }
        }

        if csCharacteristic != nil && scCharacteristic != nil {
            state = .connected
            appendLog("Ready -- CS and SC characteristics found, notifications enabled")
        } else {
            appendLog("Missing characteristics (CS=\(csCharacteristic != nil), SC=\(scCharacteristic != nil))")
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                     didUpdateValueFor characteristic: CBCharacteristic,
                     error: Error?) {
        guard error == nil, characteristic.uuid == NdnBleProtocol.scCharUUID,
              let value = characteristic.value else { return }
        appendLog("SC notification: \(value.count) bytes")
        rxData.send(value)
    }
}
