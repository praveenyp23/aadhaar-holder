package com.example.mdoc.common

import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * Minimal NDEF message builder for ISO 18013-5 NFC static handover.
 *
 * Constructs the Handover Select NDEF message that contains:
 *   1. Handover Select record (with embedded Alternative Carrier record)
 *   2. Device Engagement record (External type)
 *   3. BLE Carrier Configuration record (MIME type, OOB data)
 */
object NdefHandoverBuilder {

    private const val TNF_WELL_KNOWN  = 0x01
    private const val TNF_MIME_MEDIA  = 0x02
    private const val TNF_EXTERNAL    = 0x04

    // ── public API ────────────────────────────────────────────────────

    data class HandoverResult(
        /** Raw bytes of the full NDEF message (to be served in the NDEF file). */
        val ndefMessageBytes: ByteArray,
        /** The same bytes, for use in the session transcript handover field. */
        val handoverSelectPayload: ByteArray
    )

    /**
     * Build an NFC Forum Connection Handover 1.5 Static Handover Select message
     * advertising a BLE peripheral with [bleUuid].
     */
    fun buildStaticHandover(
        encodedDeviceEngagement: ByteArray,
        bleUuid: UUID
    ): HandoverResult {
        val carrierRef = "0"       // reference ID of the BLE carrier record
        val auxRef     = "mdoc"    // reference ID of the Device Engagement record

        // ── BLE OOB payload ──────────────────────────────────────────
        val bleOob = buildBleOobData(bleUuid)

        // ── Individual records ───────────────────────────────────────

        // 1. Handover Select record (with embedded Alternative Carrier)
        val acPayload = buildAlternativeCarrierPayload(carrierRef, auxRef)
        val acRecord  = encodeNdefRecord(
            tnf = TNF_WELL_KNOWN, type = "ac".toByteArray(),
            id = ByteArray(0), payload = acPayload,
            mb = true, me = true   // only record inside the embedded message
        )
        val hsPayload = byteArrayOf(0x15.toByte()) + acRecord   // version 1.5 + embedded

        val hsRecord = encodeNdefRecord(
            tnf = TNF_WELL_KNOWN, type = "Hs".toByteArray(),
            id = ByteArray(0), payload = hsPayload,
            mb = true, me = false
        )

        // 2. Device Engagement record
        val deRecord = encodeNdefRecord(
            tnf = TNF_EXTERNAL,
            type = "iso.org:18013:deviceengagement".toByteArray(),
            id = auxRef.toByteArray(),
            payload = encodedDeviceEngagement,
            mb = false, me = false
        )

        // 3. BLE Carrier Configuration record
        val bleRecord = encodeNdefRecord(
            tnf = TNF_MIME_MEDIA,
            type = "application/vnd.bluetooth.le.oob".toByteArray(),
            id = carrierRef.toByteArray(),
            payload = bleOob,
            mb = false, me = true
        )

        val ndefMsg = hsRecord + deRecord + bleRecord
        return HandoverResult(ndefMsg, ndefMsg)
    }

    // ── NDEF Capability Container (for NFC Forum Type 4 Tag) ─────────

    /**
     * Fixed 15-byte Capability Container for a read-only Type 4 Tag with
     * NDEF file ID 0xE104.
     */
    fun buildCapabilityContainer(): ByteArray = byteArrayOf(
        0x00, 0x0F,              // CC length
        0x20,                    // Mapping version 2.0
        0x7F, 0xFF.toByte(),     // MLe
        0x7F, 0xFF.toByte(),     // MLc
        0x04, 0x06,              // NDEF file control TLV  (T=04, L=06)
        0xE1.toByte(), 0x04,     // File identifier
        0x7F, 0xFF.toByte(),     // Max NDEF size
        0x00,                    // Read access: allowed
        0xFF.toByte()            // Write access: disallowed (static handover)
    )

    /**
     * Wraps the NDEF message bytes with a 2-byte length prefix for the
     * NDEF file content.
     */
    fun wrapAsNdefFile(ndefMsgBytes: ByteArray): ByteArray {
        val len = ndefMsgBytes.size
        return byteArrayOf(
            ((len shr 8) and 0xFF).toByte(),
            (len and 0xFF).toByte()
        ) + ndefMsgBytes
    }

    // ── internal helpers ──────────────────────────────────────────────

    private fun buildAlternativeCarrierPayload(carrierRef: String, auxRef: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x01)                                 // CPS = active
        out.write(carrierRef.length)                    // carrier data ref length
        out.write(carrierRef.toByteArray())             // carrier data ref
        out.write(0x01)                                 // number of aux refs
        out.write(auxRef.length)                        // aux ref length
        out.write(auxRef.toByteArray())                 // aux ref
        return out.toByteArray()
    }

    private fun buildBleOobData(uuid: UUID): ByteArray {
        val out = ByteArrayOutputStream()
        // LE Role: peripheral only (0x00 = Peripheral Only per BT OOB spec)
        out.write(0x02)          // EIR length (type + value = 2)
        out.write(0x1C)          // data type: LE Role
        out.write(0x00)          // value: 0x00 = peripheral only (multipaz: value=0 + MDOC role → peripheral=true)

        // Complete List of 128-bit Service UUIDs
        val uuidBytes = uuidToLittleEndian(uuid)
        out.write(uuidBytes.size + 1)   // length (type + uuid bytes)
        out.write(0x07)                  // data type: Complete List of 128-bit UUIDs
        out.write(uuidBytes)
        return out.toByteArray()
    }

    /** Convert a UUID to 16-byte little-endian (Bluetooth ordering). */
    private fun uuidToLittleEndian(uuid: UUID): ByteArray {
        val big = Iso18013Crypto.uuidToBytes(uuid)
        return big.reversedArray()
    }

    /**
     * Encode a single NDEF record with the given header flags.
     *
     *  Header byte layout:
     *    Bit 7 : MB (Message Begin)
     *    Bit 6 : ME (Message End)
     *    Bit 5 : CF (Chunk Flag) – always 0
     *    Bit 4 : SR (Short Record – payload < 256)
     *    Bit 3 : IL (ID Length present)
     *    Bits 2-0 : TNF
     */
    private fun encodeNdefRecord(
        tnf: Int, type: ByteArray, id: ByteArray, payload: ByteArray,
        mb: Boolean, me: Boolean
    ): ByteArray {
        val sr = payload.size < 256
        val il = id.isNotEmpty()

        var flags = tnf and 0x07
        if (mb) flags = flags or 0x80
        if (me) flags = flags or 0x40
        if (sr) flags = flags or 0x10
        if (il) flags = flags or 0x08

        val out = ByteArrayOutputStream()
        out.write(flags)
        out.write(type.size)
        if (sr) {
            out.write(payload.size)
        } else {
            out.write((payload.size shr 24) and 0xFF)
            out.write((payload.size shr 16) and 0xFF)
            out.write((payload.size shr 8) and 0xFF)
            out.write(payload.size and 0xFF)
        }
        if (il) out.write(id.size)
        out.write(type)
        if (il) out.write(id)
        out.write(payload)
        return out.toByteArray()
    }
}
