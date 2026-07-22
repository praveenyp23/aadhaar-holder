package com.example.mdoc.holder.ble

import java.util.UUID

/**
 * Constants + chunk framing for "OpenID for Verifiable Presentations over BLE" (openid4vp_ble
 * draft). The Verifier is the GATT peripheral; the Wallet is the GATT central.
 */
object BleProtocol {
    val SERVICE_UUID: UUID = UUID.fromString("00000001-5026-444A-9E0E-D6F2450F3A77")
    val SCAN_RESPONSE_SERVICE_UUID: UUID = UUID.fromString("00000002-5026-444A-9E0E-D6F2450F3A77")

    val REQUEST_SIZE: UUID = UUID.fromString("00000004-5026-444A-9E0E-D6F2450F3A77")      // wallet reads
    val REQUEST: UUID = UUID.fromString("00000005-5026-444A-9E0E-D6F2450F3A77")           // wallet reads
    val IDENTIFY: UUID = UUID.fromString("00000006-5026-444A-9E0E-D6F2450F3A77")          // wallet writes
    val CONTENT_SIZE: UUID = UUID.fromString("00000007-5026-444A-9E0E-D6F2450F3A77")      // wallet writes
    val SUBMIT_VC: UUID = UUID.fromString("00000008-5026-444A-9E0E-D6F2450F3A77")         // wallet writes
    val TRANSFER_SUMMARY_REQUEST: UUID = UUID.fromString("00000009-5026-444A-9E0E-D6F2450F3A77") // wallet writes
    val TRANSFER_SUMMARY_REPORT: UUID = UUID.fromString("0000000A-5026-444A-9E0E-D6F2450F3A77")  // verifier notifies
    val DISCONNECT: UUID = UUID.fromString("0000000B-5026-444A-9E0E-D6F2450F3A77")        // verifier notifies

    /** QR engagement: OPENID4VP://connect?name=<verifier>&key=<hex X25519 pubkey>. */
    const val QR_PREFIX = "OPENID4VP://connect"
    const val ADV_PREFIX = "OVP"

    // Chunk = | seq(2 BE) | payload | CRC16-CCITT-FALSE(2 BE) |
    private const val SEQ_LEN = 2
    private const val CRC_LEN = 2

    /** Splits [data] into chunks whose total size ≤ [maxChunkSize] (seq + payload + crc). */
    fun encodeChunks(data: ByteArray, maxChunkSize: Int): List<ByteArray> {
        val maxPayload = (maxChunkSize - SEQ_LEN - CRC_LEN).coerceAtLeast(1)
        val chunks = ArrayList<ByteArray>()
        var seq = 1
        var off = 0
        while (off < data.size) {
            val end = minOf(off + maxPayload, data.size)
            val payload = data.copyOfRange(off, end)
            chunks.add(frameChunk(seq, payload))
            off = end
            seq++
        }
        return chunks
    }

    private fun frameChunk(seq: Int, payload: ByteArray): ByteArray {
        val body = ByteArray(SEQ_LEN + payload.size)
        body[0] = (seq shr 8).toByte()
        body[1] = seq.toByte()
        System.arraycopy(payload, 0, body, SEQ_LEN, payload.size)
        val crc = crc16(body)
        return body + byteArrayOf((crc shr 8).toByte(), crc.toByte())
    }

    /** Returns (seq, payload) if the CRC checks out, else null. */
    fun decodeChunk(chunk: ByteArray): Pair<Int, ByteArray>? {
        if (chunk.size < SEQ_LEN + CRC_LEN) return null
        val body = chunk.copyOfRange(0, chunk.size - CRC_LEN)
        val crcGiven = ((chunk[chunk.size - 2].toInt() and 0xFF) shl 8) or (chunk[chunk.size - 1].toInt() and 0xFF)
        if (crc16(body) != crcGiven) return null
        val seq = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        return seq to body.copyOfRange(SEQ_LEN, body.size)
    }

    /** Reassembles chunk payloads (ordered by seq) into the full message. */
    fun reassemble(chunksBySeq: Map<Int, ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        chunksBySeq.toSortedMap().forEach { (_, payload) -> out.write(payload) }
        return out.toByteArray()
    }

    /** CRC16-CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection). */
    fun crc16(data: ByteArray): Int {
        var crc = 0xFFFF
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if (crc and 0x8000 != 0) (crc shl 1) xor 0x1021 else crc shl 1
                crc = crc and 0xFFFF
            }
        }
        return crc and 0xFFFF
    }
}
