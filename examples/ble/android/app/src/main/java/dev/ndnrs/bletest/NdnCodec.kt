package dev.ndnrs.bletest

/**
 * NDN packet codec — wraps BoltFFI-generated native bindings.
 *
 * When building without the Rust JNI library (e.g., for initial testing),
 * this class falls back to a pure-Kotlin minimal Interest encoder and
 * Data decoder that covers the BLE test use case.
 */
object NdnCodec {

    private var nativeLoaded = false

    init {
        try {
            System.loadLibrary("ndn_boltffi")
            nativeLoaded = true
        } catch (_: UnsatisfiedLinkError) {
            // Native library not available — use Kotlin fallback.
        }
    }

    /**
     * Encode a minimal NDN Interest packet for [name] with the given [nonce].
     */
    fun encodeInterest(name: String, nonce: Int): ByteArray {
        // Pure-Kotlin encoder for the common /ndn/ble/* test prefixes.
        return KotlinNdnEncoder.encodeInterest(name, nonce)
    }

    /**
     * Decode an NDN Data packet, returning (name, content) or null on error.
     */
    fun decodeData(wire: ByteArray): Pair<String, ByteArray>? {
        return KotlinNdnDecoder.decodeData(wire)
    }

    /**
     * Wrap a raw NDN packet in an NDNLPv2 LpPacket envelope (TLV type 0x64).
     */
    fun wrapLpPacket(payload: ByteArray): ByteArray {
        return KotlinNdnEncoder.wrapLpPacket(payload)
    }

    /**
     * Unwrap an NDNLPv2 LpPacket and extract the inner fragment.
     */
    fun unwrapLpPacket(wire: ByteArray): ByteArray? {
        return KotlinNdnDecoder.unwrapLpPacket(wire)
    }
}

// ── Minimal pure-Kotlin NDN TLV encoder ─────────────────────────────────────

private object KotlinNdnEncoder {
    fun encodeInterest(name: String, nonce: Int): ByteArray {
        val nameWire = encodeName(name)
        // Nonce TLV: type=0x0A, length=4, value=nonce
        val nonceTlv = byteArrayOf(0x0A, 0x04) + intToBytes(nonce)
        val inner = nameWire + nonceTlv
        return encodeTlv(0x05, inner)
    }

    fun wrapLpPacket(payload: ByteArray): ByteArray {
        // LpPacket type = 0x64, Fragment field type = 0x50
        val fragmentTlv = encodeTlv(0x50, payload)
        return encodeTlv(0x64, fragmentTlv)
    }

    private fun encodeName(name: String): ByteArray {
        val components = name.trim('/').split('/').filter { it.isNotEmpty() }
        var inner = ByteArray(0)
        for (comp in components) {
            inner += encodeTlv(0x08, comp.toByteArray(Charsets.UTF_8))
        }
        return encodeTlv(0x07, inner)
    }

    private fun encodeTlv(type: Int, value: ByteArray): ByteArray {
        return encodeVarNumber(type) + encodeVarNumber(value.size) + value
    }

    private fun encodeVarNumber(n: Int): ByteArray {
        return when {
            n <= 252 -> byteArrayOf(n.toByte())
            n <= 0xFFFF -> byteArrayOf(
                253.toByte(),
                (n shr 8).toByte(),
                (n and 0xFF).toByte()
            )
            else -> byteArrayOf(
                254.toByte(),
                (n shr 24).toByte(),
                ((n shr 16) and 0xFF).toByte(),
                ((n shr 8) and 0xFF).toByte(),
                (n and 0xFF).toByte()
            )
        }
    }

    private fun intToBytes(v: Int): ByteArray = byteArrayOf(
        (v shr 24).toByte(),
        ((v shr 16) and 0xFF).toByte(),
        ((v shr 8) and 0xFF).toByte(),
        (v and 0xFF).toByte()
    )
}

// ── Minimal pure-Kotlin NDN TLV decoder ─────────────────────────────────────

private object KotlinNdnDecoder {
    fun decodeData(wire: ByteArray): Pair<String, ByteArray>? {
        var pos = 0
        val (type, typeLen) = readVarNumber(wire, pos) ?: return null
        pos += typeLen
        if (type != 0x06L) return null // Not a Data packet

        val (length, lengthLen) = readVarNumber(wire, pos) ?: return null
        pos += lengthLen
        val end = pos + length.toInt()

        var name: String? = null
        var content = ByteArray(0)

        while (pos < end) {
            val (fieldType, ftLen) = readVarNumber(wire, pos) ?: break
            pos += ftLen
            val (fieldLen, flLen) = readVarNumber(wire, pos) ?: break
            pos += flLen
            val fieldEnd = pos + fieldLen.toInt()

            when (fieldType) {
                0x07L -> name = decodeName(wire, pos, fieldEnd) // Name
                0x15L -> content = wire.copyOfRange(pos, fieldEnd) // Content
            }
            pos = fieldEnd
        }

        return name?.let { Pair(it, content) }
    }

    fun unwrapLpPacket(wire: ByteArray): ByteArray? {
        var pos = 0
        val (type, typeLen) = readVarNumber(wire, pos) ?: return null
        pos += typeLen
        if (type != 0x64L) return null // Not an LpPacket

        val (length, lengthLen) = readVarNumber(wire, pos) ?: return null
        pos += lengthLen
        val end = pos + length.toInt()

        while (pos < end) {
            val (fieldType, ftLen) = readVarNumber(wire, pos) ?: break
            pos += ftLen
            val (fieldLen, flLen) = readVarNumber(wire, pos) ?: break
            pos += flLen
            val fieldEnd = pos + fieldLen.toInt()

            if (fieldType == 0x50L) { // Fragment
                return wire.copyOfRange(pos, fieldEnd)
            }
            pos = fieldEnd
        }
        return null
    }

    private fun decodeName(wire: ByteArray, start: Int, end: Int): String {
        val components = mutableListOf<String>()
        var pos = start
        while (pos < end) {
            val (_, ftLen) = readVarNumber(wire, pos) ?: break // component type
            pos += ftLen
            val (compLen, clLen) = readVarNumber(wire, pos) ?: break
            pos += clLen
            val compEnd = pos + compLen.toInt()
            components.add(String(wire, pos, compLen.toInt(), Charsets.UTF_8))
            pos = compEnd
        }
        return "/" + components.joinToString("/")
    }

    private fun readVarNumber(buf: ByteArray, offset: Int): Pair<Long, Int>? {
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
}
