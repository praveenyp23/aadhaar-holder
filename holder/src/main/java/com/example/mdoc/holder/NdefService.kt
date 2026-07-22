package com.example.mdoc.holder

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.mdoc.common.NdefHandoverBuilder

/**
 * NFC Forum Type 4 Tag emulation for ISO 18013-5 NFC static handover.
 *
 * The multipaz-identity-reader performs NFC engagement by:
 *   1. SELECT Application  (NDEF AID D2760000850101)
 *   2. SELECT File          (CC = 0xE103, NDEF = 0xE104)
 *   3. READ BINARY          (reads file data at offset)
 *
 * The NDEF file contains a Handover Select message with Device Engagement
 * and BLE carrier configuration.  After reading it the reader connects
 * to the holder's BLE peripheral for the actual data transfer.
 */
class NdefService : HostApduService() {

    companion object {
        private const val TAG = "MDOC_NDEF_SERVICE"

        // NDEF Application AID (NFC Forum Type 4 Tag)
        private const val NDEF_AID = "D2760000850101"

        // File IDs
        private const val FILE_CC   = 0xE103
        private const val FILE_NDEF = 0xE104

        // APDU INS codes
        private const val INS_SELECT      = 0xA4.toByte()
        private const val INS_READ_BINARY = 0xB0.toByte()

        // SW status words
        private val SW_OK           = byteArrayOf(0x90.toByte(), 0x00)
        private val SW_NOT_FOUND    = byteArrayOf(0x6A.toByte(), 0x82.toByte())
        private val SW_INS_NOT_SUP  = byteArrayOf(0x6D.toByte(), 0x00)
        private val SW_WRONG_LEN    = byteArrayOf(0x67.toByte(), 0x00)

        // ── Shared state set by MainActivity before presentation ─────
        @Volatile var ndefFileContent: ByteArray? = null
        @Volatile var handoverPayload: ByteArray? = null
    }

    private var ndefAppSelected = false
    private var selectedFileId  = 0
    private var selectedFileData = ByteArray(0)

    // Pre-built Capability Container
    private val ccData = NdefHandoverBuilder.buildCapabilityContainer()

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "NdefService created — ndefFileContent=${ndefFileContent?.size ?: "null"} bytes")
    }

    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray {
        if (apdu.size < 4) return SW_WRONG_LEN
        val ins = apdu[1]
        val p1  = apdu[2].toInt() and 0xFF
        Log.d(TAG, ">>> APDU received: INS=${"%02X".format(ins)} P1=${"%02X".format(p1)} len=${apdu.size} hex=${apdu.take(10).joinToString("") { "%02X".format(it) }}...")

        return when (ins) {
            INS_SELECT -> {
                if (p1 == 0x04) handleSelectApplication(apdu)
                else            handleSelectFile(apdu)
            }
            INS_READ_BINARY -> handleReadBinary(apdu)
            else -> {
                Log.w(TAG, "Unsupported INS: ${"%02X".format(ins)}")
                SW_INS_NOT_SUP
            }
        }
    }

    // ── SELECT Application (P1=0x04) ──────────────────────────────────

    private fun handleSelectApplication(apdu: ByteArray): ByteArray {
        if (apdu.size < 5) return SW_WRONG_LEN
        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return SW_WRONG_LEN
        val aid = apdu.copyOfRange(5, 5 + lc).toHex()
        Log.d(TAG, "SELECT APP aid=$aid")

        if (aid.equals(NDEF_AID, ignoreCase = true)) {
            ndefAppSelected = true
            selectedFileId = 0
            return SW_OK
        }
        return SW_NOT_FOUND
    }

    // ── SELECT File (P1=0x00) ─────────────────────────────────────────

    private fun handleSelectFile(apdu: ByteArray): ByteArray {
        if (!ndefAppSelected) return SW_NOT_FOUND
        if (apdu.size < 7) return SW_WRONG_LEN
        val fileId = ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
        Log.d(TAG, "SELECT FILE id=${"%04X".format(fileId)}")

        when (fileId) {
            FILE_CC -> {
                selectedFileId = fileId
                selectedFileData = ccData
            }
            FILE_NDEF -> {
                selectedFileId = fileId
                val ndefMsg = ndefFileContent
                if (ndefMsg != null) {
                    selectedFileData = NdefHandoverBuilder.wrapAsNdefFile(ndefMsg)
                    Log.d(TAG, "NDEF file selected: ${selectedFileData.size} bytes (msg=${ndefMsg.size})")
                } else {
                    Log.w(TAG, "NDEF file not configured – returning empty")
                    selectedFileData = byteArrayOf(0x00, 0x00)
                }
            }
            else -> {
                Log.w(TAG, "Unknown file id ${"%04X".format(fileId)}")
                return SW_NOT_FOUND
            }
        }
        return SW_OK
    }

    // ── READ BINARY ───────────────────────────────────────────────────

    private fun handleReadBinary(apdu: ByteArray): ByteArray {
        if (selectedFileId == 0) return SW_NOT_FOUND
        val offset = ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        val le = if (apdu.size >= 5) (apdu[4].toInt() and 0xFF).let { if (it == 0) 256 else it } else 256
        Log.d(TAG, "READ BINARY offset=$offset le=$le fileSize=${selectedFileData.size}")

        if (offset >= selectedFileData.size) return SW_NOT_FOUND
        val end = minOf(offset + le, selectedFileData.size)
        return selectedFileData.copyOfRange(offset, end) + SW_OK
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "Deactivated reason=$reason (0=LINK_LOSS, 1=DESELECTED)")
        ndefAppSelected = false
        selectedFileId = 0
    }

    private fun ByteArray.toHex() = joinToString("") { "%02X".format(it) }
}
