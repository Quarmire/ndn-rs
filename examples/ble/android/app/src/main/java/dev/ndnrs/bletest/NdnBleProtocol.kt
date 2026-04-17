package dev.ndnrs.bletest

import java.util.UUID

/**
 * NDN-over-BLE protocol constants and framing helpers.
 *
 * Supports two framing modes:
 * - **NDNLPv2** (macOS / Linux desktop BleFace)
 * - **NDNts 1-byte header** (ESP32 / embedded EmbeddedBleFace)
 */
object NdnBleProtocol {
    /** NDN BLE GATT primary service UUID (NDNts / esp8266ndn interop). */
    val SERVICE_UUID: UUID = UUID.fromString("099577e3-0788-412a-8824-395084d97391")

    /** CS characteristic — client writes Interests here (Write Without Response). */
    val CS_CHAR_UUID: UUID = UUID.fromString("cc5abb89-a541-46d8-a351-2f95a6a81f49")

    /** SC characteristic — server notifies Data packets here (Notify). */
    val SC_CHAR_UUID: UUID = UUID.fromString("972f9527-0d83-4261-b95d-b1b2fc73bde4")

    enum class FramingMode { NDNLPV2, NDNTS_BLE }

    // ── NDNts 1-byte header framing ──────────────────────────────────────

    /**
     * Fragment [packet] using NDNts BLE 1-byte header framing.
     *
     * Each fragment has a 1-byte header: first fragment = 0x80 | seq,
     * continuation = seq & 0x7F. If the packet fits in [maxPayload] bytes
     * (without header), it's sent unfragmented (no header).
     */
    fun ndntsFrame(packet: ByteArray, maxPayload: Int): List<ByteArray> {
        if (packet.size <= maxPayload) {
            // Unfragmented — send raw (no header byte).
            return listOf(packet)
        }

        val fragPayload = maxPayload - 1 // reserve 1 byte for header
        val fragments = mutableListOf<ByteArray>()
        var offset = 0
        var seq: Byte = 0
        var isFirst = true

        while (offset < packet.size) {
            val end = minOf(offset + fragPayload, packet.size)
            val chunk = packet.copyOfRange(offset, end)
            val header = if (isFirst) {
                isFirst = false
                (0x80.toByte().toInt() or (seq.toInt() and 0x7F)).toByte()
            } else {
                (seq.toInt() and 0x7F).toByte()
            }
            seq = ((seq + 1) and 0x7F).toByte()

            val frag = ByteArray(1 + chunk.size)
            frag[0] = header
            chunk.copyInto(frag, 1)
            fragments.add(frag)
            offset = end
        }
        return fragments
    }

    /**
     * Reassemble NDNts BLE 1-byte header framed fragments.
     *
     * Returns null until a complete TLV packet has been received.
     */
    class NdntsReassembler {
        private var buffer = ByteArray(0)
        private var active = false

        fun feed(fragment: ByteArray): ByteArray? {
            if (fragment.isEmpty()) return null

            val firstByte = fragment[0].toInt() and 0xFF
            if (firstByte and 0x80 != 0) {
                // First fragment — start fresh.
                buffer = fragment.copyOfRange(1, fragment.size)
                active = true
            } else if (active) {
                // Continuation fragment.
                buffer += fragment.copyOfRange(1, fragment.size)
            } else {
                // Unfragmented packet (no header byte).
                return fragment
            }

            // Check if we have a complete TLV packet.
            return checkComplete()
        }

        private fun checkComplete(): ByteArray? {
            val end = tlvPacketEnd(buffer) ?: return null
            val pkt = buffer.copyOfRange(0, end)
            buffer = buffer.copyOfRange(end, buffer.size)
            if (buffer.isEmpty()) active = false
            return pkt
        }

        fun reset() {
            buffer = ByteArray(0)
            active = false
        }
    }
}

/** Parse a TLV var-number from [buf] at [offset]. Returns (value, bytesConsumed) or null. */
private fun parseVarNumber(buf: ByteArray, offset: Int): Pair<Long, Int>? {
    if (offset >= buf.size) return null
    val b = buf[offset].toInt() and 0xFF
    return when {
        b <= 252 -> Pair(b.toLong(), 1)
        b == 253 && offset + 3 <= buf.size -> {
            val v = ((buf[offset + 1].toInt() and 0xFF) shl 8) or
                    (buf[offset + 2].toInt() and 0xFF)
            Pair(v.toLong(), 3)
        }
        b == 254 && offset + 5 <= buf.size -> {
            val v = ((buf[offset + 1].toLong() and 0xFF) shl 24) or
                    ((buf[offset + 2].toLong() and 0xFF) shl 16) or
                    ((buf[offset + 3].toLong() and 0xFF) shl 8) or
                    (buf[offset + 4].toLong() and 0xFF)
            Pair(v, 5)
        }
        else -> null
    }
}

/** Return the total byte length of the first complete TLV packet in [buf], or null. */
private fun tlvPacketEnd(buf: ByteArray): Int? {
    val (_, typeLen) = parseVarNumber(buf, 0) ?: return null
    val (length, lengthLen) = parseVarNumber(buf, typeLen) ?: return null
    val total = typeLen + lengthLen + length.toInt()
    return if (buf.size >= total) total else null
}
