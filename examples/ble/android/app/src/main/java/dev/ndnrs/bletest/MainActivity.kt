package dev.ndnrs.bletest

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import java.text.SimpleDateFormat
import java.util.*

/**
 * NDN BLE test activity.
 *
 * Scans for NDN BLE peripherals (macOS BleFace or ESP32 EmbeddedBleFace),
 * connects, sends an Interest, and displays the received Data.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var bleClient: BleClient
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val reassembler = NdnBleProtocol.NdntsReassembler()

    private lateinit var btnScan: Button
    private lateinit var btnSend: Button
    private lateinit var btnDisconnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvDevices: TextView
    private lateinit var lvDevices: ListView
    private lateinit var tvLog: TextView
    private lateinit var modeMacos: RadioButton
    private lateinit var modeEsp32: RadioButton

    private val deviceListAdapter by lazy {
        ArrayAdapter<String>(this, android.R.layout.simple_list_item_1)
    }
    private val discoveredDevices = mutableListOf<BleClient.ScannedDevice>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnScan = findViewById(R.id.btnScan)
        btnSend = findViewById(R.id.btnSend)
        btnDisconnect = findViewById(R.id.btnDisconnect)
        tvStatus = findViewById(R.id.tvStatus)
        tvDevices = findViewById(R.id.tvDevices)
        lvDevices = findViewById(R.id.lvDevices)
        tvLog = findViewById(R.id.tvLog)
        modeMacos = findViewById(R.id.modeMacos)
        modeEsp32 = findViewById(R.id.modeEsp32)

        lvDevices.adapter = deviceListAdapter

        bleClient = BleClient(this)

        btnScan.setOnClickListener { onScan() }
        btnSend.setOnClickListener { onSendInterest() }
        btnDisconnect.setOnClickListener { bleClient.disconnect() }

        lvDevices.setOnItemClickListener { _, _, position, _ ->
            if (position < discoveredDevices.size) {
                bleClient.connect(discoveredDevices[position].device)
            }
        }

        // Observe state changes.
        scope.launch {
            bleClient.state.collectLatest { state ->
                when (state) {
                    is BleClient.State.Idle -> {
                        tvStatus.text = "Status: idle"
                        btnScan.isEnabled = true
                        btnSend.isEnabled = false
                        btnDisconnect.isEnabled = false
                        hideDeviceList()
                    }
                    is BleClient.State.Scanning -> {
                        tvStatus.text = "Status: scanning ���"
                        btnScan.isEnabled = false
                        showDeviceList()
                    }
                    is BleClient.State.Connecting -> {
                        tvStatus.text = "Status: connecting …"
                        hideDeviceList()
                    }
                    is BleClient.State.Connected -> {
                        tvStatus.text = "Status: connected"
                        btnScan.isEnabled = false
                        btnSend.isEnabled = true
                        btnDisconnect.isEnabled = true
                        hideDeviceList()
                    }
                    is BleClient.State.Disconnected -> {
                        tvStatus.text = "Status: disconnected"
                        btnScan.isEnabled = true
                        btnSend.isEnabled = false
                        btnDisconnect.isEnabled = false
                    }
                    is BleClient.State.Found -> {}
                }
            }
        }

        // Observe log events.
        scope.launch {
            bleClient.events.collect { msg ->
                appendLog(msg)
            }
        }

        // Observe scanned devices.
        scope.launch {
            bleClient.scannedDevices.collectLatest { devices ->
                discoveredDevices.clear()
                discoveredDevices.addAll(devices)
                deviceListAdapter.clear()
                devices.forEach { d ->
                    deviceListAdapter.add("${d.name ?: "unknown"} [${d.device.address}]")
                }
            }
        }

        // Observe incoming SC notifications.
        scope.launch {
            bleClient.rxData.collect { raw ->
                handleRxData(raw)
            }
        }

        requestPermissionsIfNeeded()
    }

    override fun onDestroy() {
        super.onDestroy()
        bleClient.disconnect()
        scope.cancel()
    }

    // ── UI helpers ───────────────────────────────────────────────────────

    private fun showDeviceList() {
        tvDevices.visibility = TextView.VISIBLE
        lvDevices.visibility = ListView.VISIBLE
    }

    private fun hideDeviceList() {
        tvDevices.visibility = TextView.GONE
        lvDevices.visibility = ListView.GONE
    }

    private fun appendLog(msg: String) {
        val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val line = "[$ts] $msg\n"
        tvLog.append(line)
        // Auto-scroll: find parent ScrollView and scroll to bottom.
        (tvLog.parent as? android.widget.ScrollView)?.fullScroll(android.widget.ScrollView.FOCUS_DOWN)
    }

    private val framingMode: NdnBleProtocol.FramingMode
        get() = if (modeMacos.isChecked) NdnBleProtocol.FramingMode.NDNLPV2
                else NdnBleProtocol.FramingMode.NDNTS_BLE

    // ── Actions ──────────────────────────────────────────────────────────

    private fun onScan() {
        discoveredDevices.clear()
        deviceListAdapter.clear()
        bleClient.startScan()
        // Auto-stop after 10 seconds.
        scope.launch {
            delay(10_000)
            bleClient.stopScan()
        }
    }

    private fun onSendInterest() {
        val name = if (modeEsp32.isChecked) "/ndn/ble/esp32" else "/ndn/ble/test"
        val nonce = Random().nextInt()
        val interestWire = NdnCodec.encodeInterest(name, nonce)

        appendLog("Sending Interest: $name (${interestWire.size} bytes, nonce=$nonce)")

        when (framingMode) {
            NdnBleProtocol.FramingMode.NDNLPV2 -> {
                val lpWire = NdnCodec.wrapLpPacket(interestWire)
                appendLog("  NDNLPv2 envelope: ${lpWire.size} bytes")
                val ok = bleClient.writeCs(lpWire)
                appendLog(if (ok) "  Written to CS" else "  Write FAILED")
            }
            NdnBleProtocol.FramingMode.NDNTS_BLE -> {
                // Assume 244-byte max payload (ESP32-C3 typical).
                val fragments = NdnBleProtocol.ndntsFrame(interestWire, 244)
                appendLog("  NDNts framing: ${fragments.size} fragment(s)")
                for ((i, frag) in fragments.withIndex()) {
                    val ok = bleClient.writeCs(frag)
                    appendLog("    frag[$i]: ${frag.size} bytes — ${if (ok) "OK" else "FAILED"}")
                }
            }
        }

        reassembler.reset()
    }

    private fun handleRxData(raw: ByteArray) {
        appendLog("RX: ${raw.size} bytes")
        when (framingMode) {
            NdnBleProtocol.FramingMode.NDNLPV2 -> {
                val inner = NdnCodec.unwrapLpPacket(raw)
                if (inner == null) {
                    appendLog("  Failed to unwrap LpPacket")
                    return
                }
                decodeAndDisplay(inner)
            }
            NdnBleProtocol.FramingMode.NDNTS_BLE -> {
                val complete = reassembler.feed(raw)
                if (complete != null) {
                    decodeAndDisplay(complete)
                } else {
                    appendLog("  Fragment buffered, waiting for more …")
                }
            }
        }
    }

    private fun decodeAndDisplay(wire: ByteArray) {
        val result = NdnCodec.decodeData(wire)
        if (result != null) {
            val (name, content) = result
            val text = String(content, Charsets.UTF_8)
            appendLog("Data received!")
            appendLog("  Name: $name")
            appendLog("  Content: $text")
            tvStatus.text = "Status: Data received!"
        } else {
            appendLog("  Failed to decode Data packet (${wire.size} bytes)")
        }
    }

    // ── Permissions ──────────────────────────────────────────────────────

    private fun requestPermissionsIfNeeded() {
        val perms = arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
        val needed = perms.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, needed.toTypedArray(), 1)
        }
    }
}
