package dev.ndnrs.bletest

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * BLE GATT central client for NDN-over-BLE testing.
 *
 * Scans for the NDN BLE service, connects, and provides read/write access
 * to the CS (write) and SC (notify) characteristics.
 */
@SuppressLint("MissingPermission")
class BleClient(private val context: Context) {

    sealed class State {
        data object Idle : State()
        data object Scanning : State()
        data class Found(val device: BluetoothDevice, val name: String?) : State()
        data object Connecting : State()
        data object Connected : State()
        data object Disconnected : State()
    }

    data class ScannedDevice(val device: BluetoothDevice, val name: String?)

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state

    private val _events = MutableSharedFlow<String>(extraBufferCapacity = 64)
    val events: SharedFlow<String> = _events

    private val _rxData = MutableSharedFlow<ByteArray>(extraBufferCapacity = 16)
    val rxData: SharedFlow<ByteArray> = _rxData

    private val _scannedDevices = MutableStateFlow<List<ScannedDevice>>(emptyList())
    val scannedDevices: StateFlow<List<ScannedDevice>> = _scannedDevices

    private val adapter: BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private var scanner: BluetoothLeScanner? = null
    private var gatt: BluetoothGatt? = null
    private var csChar: BluetoothGattCharacteristic? = null
    private var scChar: BluetoothGattCharacteristic? = null

    // ── Scanning ─────────────────────────────────────────────────────────

    fun startScan() {
        val adapter = this.adapter ?: run {
            _events.tryEmit("Bluetooth not available")
            return
        }
        if (!adapter.isEnabled) {
            _events.tryEmit("Bluetooth is disabled")
            return
        }

        scanner = adapter.bluetoothLeScanner
        _scannedDevices.value = emptyList()
        _state.value = State.Scanning

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(NdnBleProtocol.SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        _events.tryEmit("Scanning for NDN BLE peripherals …")
        scanner?.startScan(listOf(filter), settings, scanCallback)
    }

    fun stopScan() {
        scanner?.stopScan(scanCallback)
        if (_state.value == State.Scanning) {
            _state.value = State.Idle
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val name = result.scanRecord?.deviceName ?: device.name
            val current = _scannedDevices.value
            if (current.none { it.device.address == device.address }) {
                _scannedDevices.value = current + ScannedDevice(device, name)
                _events.tryEmit("Found: ${name ?: "unknown"} [${device.address}]")
            }
        }

        override fun onScanFailed(errorCode: Int) {
            _events.tryEmit("Scan failed: error $errorCode")
            _state.value = State.Idle
        }
    }

    // ── Connection ───────────────────────────────────────────────────────

    fun connect(device: BluetoothDevice) {
        stopScan()
        _state.value = State.Connecting
        _events.tryEmit("Connecting to ${device.address} …")
        gatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    fun disconnect() {
        gatt?.disconnect()
        gatt?.close()
        gatt = null
        csChar = null
        scChar = null
        _state.value = State.Disconnected
        _events.tryEmit("Disconnected")
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    _events.tryEmit("Connected, discovering services …")
                    gatt.requestMtu(517) // Request max MTU for BLE 5.x
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    _state.value = State.Disconnected
                    _events.tryEmit("Disconnected (status=$status)")
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            _events.tryEmit("MTU negotiated: $mtu bytes")
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                _events.tryEmit("Service discovery failed: status=$status")
                return
            }

            val service = gatt.getService(NdnBleProtocol.SERVICE_UUID)
            if (service == null) {
                _events.tryEmit("NDN BLE service not found!")
                return
            }

            csChar = service.getCharacteristic(NdnBleProtocol.CS_CHAR_UUID)
            scChar = service.getCharacteristic(NdnBleProtocol.SC_CHAR_UUID)

            if (csChar == null || scChar == null) {
                _events.tryEmit("NDN characteristics not found (CS=${csChar != null}, SC=${scChar != null})")
                return
            }

            // Subscribe to SC notifications.
            gatt.setCharacteristicNotification(scChar!!, true)
            val descriptor = scChar!!.getDescriptor(
                java.util.UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
            )
            if (descriptor != null) {
                gatt.writeDescriptor(
                    descriptor,
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                )
            }

            _state.value = State.Connected
            _events.tryEmit("Ready — CS and SC characteristics found, notifications enabled")
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid == NdnBleProtocol.SC_CHAR_UUID) {
                _events.tryEmit("SC notification: ${value.size} bytes")
                _rxData.tryEmit(value)
            }
        }
    }

    // ── Write ────────────────────────────────────────────────────────────

    /** Write raw bytes to the CS (client→server) characteristic. */
    fun writeCs(data: ByteArray): Boolean {
        val cs = csChar ?: return false
        val g = gatt ?: return false
        val result = g.writeCharacteristic(
            cs,
            data,
            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        )
        return result == BluetoothStatusCodes.SUCCESS
    }
}
