import CoreBluetooth
import Foundation

/// NDN-over-BLE protocol constants and framing helpers.
enum NdnBleProtocol {
    /// NDN BLE GATT primary service UUID (NDNts / esp8266ndn interop).
    static let serviceUUID = CBUUID(string: "099577e3-0788-412a-8824-395084d97391")

    /// CS characteristic -- client writes Interests here (Write Without Response).
    static let csCharUUID = CBUUID(string: "cc5abb89-a541-46d8-a351-2f95a6a81f49")

    /// SC characteristic -- server notifies Data packets here (Notify).
    static let scCharUUID = CBUUID(string: "972f9527-0d83-4261-b95d-b1b2fc73bde4")

    enum FramingMode: String, CaseIterable {
        case ndnlpv2 = "macOS (NDNLPv2)"
        case ndntsBle = "ESP32 (NDNts)"
    }

    // MARK: - NDNts 1-byte header framing

    /// Fragment a packet using NDNts BLE 1-byte header framing.
    static func ndntsFrame(packet: Data, maxPayload: Int) -> [Data] {
        if packet.count <= maxPayload {
            return [packet]
        }
        let fragPayload = maxPayload - 1
        var fragments: [Data] = []
        var offset = 0
        var seq: UInt8 = 0
        var isFirst = true

        while offset < packet.count {
            let end = min(offset + fragPayload, packet.count)
            let chunk = packet[offset..<end]
            let header: UInt8
            if isFirst {
                isFirst = false
                header = 0x80 | (seq & 0x7F)
            } else {
                header = seq & 0x7F
            }
            seq = (seq &+ 1) & 0x7F

            var frag = Data(capacity: 1 + chunk.count)
            frag.append(header)
            frag.append(chunk)
            fragments.append(frag)
            offset = end
        }
        return fragments
    }

    /// Reassembler for NDNts BLE 1-byte header framed fragments.
    class NdntsReassembler {
        private var buffer = Data()
        private var active = false

        func feed(_ fragment: Data) -> Data? {
            guard !fragment.isEmpty else { return nil }

            let firstByte = fragment[fragment.startIndex]
            if firstByte & 0x80 != 0 {
                buffer = fragment.dropFirst()
                active = true
            } else if active {
                buffer.append(fragment.dropFirst())
            } else {
                return Data(fragment)
            }

            return checkComplete()
        }

        func reset() {
            buffer = Data()
            active = false
        }

        private func checkComplete() -> Data? {
            guard let end = tlvPacketEnd(buffer) else { return nil }
            let pkt = buffer.prefix(end)
            buffer = buffer.dropFirst(end)
            if buffer.isEmpty { active = false }
            return Data(pkt)
        }
    }
}

// MARK: - Minimal NDN TLV codec (pure Swift)

enum NdnCodec {
    /// Encode a minimal NDN Interest packet.
    static func encodeInterest(name: String, nonce: UInt32) -> Data {
        let nameWire = encodeName(name)
        let nonceTlv = Data([0x0A, 0x04]) + withUnsafeBytes(of: nonce.bigEndian) { Data($0) }
        let inner = nameWire + nonceTlv
        return encodeTlv(type: 0x05, value: inner)
    }

    /// Decode an NDN Data packet, returning (name, content) or nil.
    static func decodeData(_ wire: Data) -> (name: String, content: Data)? {
        var pos = wire.startIndex
        guard let (type, typeLen) = readVarNumber(wire, at: pos) else { return nil }
        pos += typeLen
        guard type == 0x06 else { return nil }

        guard let (length, lengthLen) = readVarNumber(wire, at: pos) else { return nil }
        pos += lengthLen
        let end = pos + Int(length)

        var name: String?
        var content = Data()

        while pos < end {
            guard let (fieldType, ftLen) = readVarNumber(wire, at: pos) else { break }
            pos += ftLen
            guard let (fieldLen, flLen) = readVarNumber(wire, at: pos) else { break }
            pos += flLen
            let fieldEnd = pos + Int(fieldLen)

            switch fieldType {
            case 0x07: name = decodeName(wire, from: pos, to: fieldEnd)
            case 0x15: content = wire[pos..<fieldEnd]
            default: break
            }
            pos = fieldEnd
        }
        guard let n = name else { return nil }
        return (n, content)
    }

    /// Wrap a raw NDN packet in an NDNLPv2 LpPacket envelope.
    static func wrapLpPacket(_ payload: Data) -> Data {
        let fragmentTlv = encodeTlv(type: 0x50, value: payload)
        return encodeTlv(type: 0x64, value: fragmentTlv)
    }

    /// Unwrap an NDNLPv2 LpPacket and extract the inner fragment.
    static func unwrapLpPacket(_ wire: Data) -> Data? {
        var pos = wire.startIndex
        guard let (type, typeLen) = readVarNumber(wire, at: pos), type == 0x64 else { return nil }
        pos += typeLen
        guard let (length, lengthLen) = readVarNumber(wire, at: pos) else { return nil }
        pos += lengthLen
        let end = pos + Int(length)

        while pos < end {
            guard let (fieldType, ftLen) = readVarNumber(wire, at: pos) else { break }
            pos += ftLen
            guard let (fieldLen, flLen) = readVarNumber(wire, at: pos) else { break }
            pos += flLen
            let fieldEnd = pos + Int(fieldLen)
            if fieldType == 0x50 { return Data(wire[pos..<fieldEnd]) }
            pos = fieldEnd
        }
        return nil
    }

    // MARK: - Private helpers

    private static func encodeName(_ name: String) -> Data {
        let components = name.split(separator: "/").filter { !$0.isEmpty }
        var inner = Data()
        for comp in components {
            inner.append(encodeTlv(type: 0x08, value: Data(comp.utf8)))
        }
        return encodeTlv(type: 0x07, value: inner)
    }

    private static func encodeTlv(type: Int, value: Data) -> Data {
        return encodeVarNumber(type) + encodeVarNumber(value.count) + value
    }

    private static func encodeVarNumber(_ n: Int) -> Data {
        if n <= 252 {
            return Data([UInt8(n)])
        } else if n <= 0xFFFF {
            return Data([253, UInt8(n >> 8), UInt8(n & 0xFF)])
        } else {
            return Data([254, UInt8(n >> 24), UInt8((n >> 16) & 0xFF),
                         UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
        }
    }

    private static func decodeName(_ wire: Data, from start: Int, to end: Int) -> String {
        var components: [String] = []
        var pos = start
        while pos < end {
            guard let (_, ftLen) = readVarNumber(wire, at: pos) else { break }
            pos += ftLen
            guard let (compLen, clLen) = readVarNumber(wire, at: pos) else { break }
            pos += clLen
            let compEnd = pos + Int(compLen)
            if let s = String(data: wire[pos..<compEnd], encoding: .utf8) {
                components.append(s)
            }
            pos = compEnd
        }
        return "/" + components.joined(separator: "/")
    }

    private static func readVarNumber(_ buf: Data, at offset: Int) -> (UInt64, Int)? {
        guard offset < buf.endIndex else { return nil }
        let b = buf[offset]
        switch b {
        case 0...252:
            return (UInt64(b), 1)
        case 253:
            guard offset + 3 <= buf.endIndex else { return nil }
            let v = (UInt64(buf[offset + 1]) << 8) | UInt64(buf[offset + 2])
            return (v, 3)
        case 254:
            guard offset + 5 <= buf.endIndex else { return nil }
            let v = (UInt64(buf[offset + 1]) << 24) | (UInt64(buf[offset + 2]) << 16) |
                    (UInt64(buf[offset + 3]) << 8) | UInt64(buf[offset + 4])
            return (v, 5)
        default:
            return nil
        }
    }
}

/// Check if `buf` contains a complete TLV packet and return its total length.
private func tlvPacketEnd(_ buf: Data) -> Int? {
    let start = buf.startIndex
    guard let (_, typeLen) = readVarNumberGlobal(buf, at: start) else { return nil }
    guard let (length, lengthLen) = readVarNumberGlobal(buf, at: start + typeLen) else { return nil }
    let total = typeLen + lengthLen + Int(length)
    return buf.count >= total ? total : nil
}

private func readVarNumberGlobal(_ buf: Data, at offset: Int) -> (UInt64, Int)? {
    guard offset < buf.endIndex else { return nil }
    let b = buf[offset]
    switch b {
    case 0...252: return (UInt64(b), 1)
    case 253:
        guard offset + 3 <= buf.endIndex else { return nil }
        return ((UInt64(buf[offset + 1]) << 8) | UInt64(buf[offset + 2]), 3)
    case 254:
        guard offset + 5 <= buf.endIndex else { return nil }
        return ((UInt64(buf[offset + 1]) << 24) | (UInt64(buf[offset + 2]) << 16) |
                (UInt64(buf[offset + 3]) << 8) | UInt64(buf[offset + 4]), 5)
    default: return nil
    }
}
