package com.mdocholder.app.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import java.io.File

/**
 * ISO 18013-5 compliant Host Card Emulation (HCE) service for mDoc transfer via NFC
 * Implements phone-to-phone mDoc transfer using NFC
 */
class MdocHostApduService : HostApduService() {

    companion object {
        private const val TAG = "MdocHostApduService"
        
        // ISO 18013-5 AID for mDL/mDoc
        private val AID_MDL = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x24.toByte(), 0x80.toByte(), 0x04.toByte(), 0x00.toByte()
        )
        
        // APDU Status codes
        private val STATUS_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val STATUS_FAILED = byteArrayOf(0x6F.toByte(), 0x00.toByte())
        private val STATUS_FILE_NOT_FOUND = byteArrayOf(0x6A.toByte(), 0x82.toByte())
        
        // APDU Command codes
        private const val CLA_ISO7816 = 0x00.toByte()
        private const val INS_SELECT = 0xA4.toByte()
        private const val INS_ENVELOPE = 0xC3.toByte()
        private const val INS_READ_BINARY = 0xB0.toByte()
    }

    private var mdocData: ByteArray? = null
    private var isSelected = false
    private var dataOffset = 0

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "HCE Service created")
        loadMdocData()
    }

    private fun loadMdocData() {
        try {
            // Load from app assets
            val base64Data = assets.open("mdoc_b64.txt").bufferedReader().use { it.readText().trim() }
            mdocData = android.util.Base64.decode(base64Data, android.util.Base64.DEFAULT)
            Log.i(TAG, "Loaded mDoc data from assets: ${mdocData?.size} bytes")
        } catch (e: Exception) {
            Log.e(TAG, "Error loading mDoc data", e)
        }
    }

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null || commandApdu.size < 4) {
            Log.w(TAG, "Invalid APDU received")
            return STATUS_FAILED
        }

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        Log.d(TAG, "Received APDU - CLA: ${cla.toHex()}, INS: ${ins.toHex()}, Length: ${commandApdu.size}")

        return when (ins) {
            INS_SELECT -> handleSelectCommand(commandApdu)
            INS_ENVELOPE -> handleEnvelopeCommand(commandApdu)
            INS_READ_BINARY -> handleReadBinaryCommand(commandApdu)
            else -> {
                Log.w(TAG, "Unsupported INS: ${ins.toHex()}")
                STATUS_FAILED
            }
        }
    }

    private fun handleSelectCommand(apdu: ByteArray): ByteArray {
        // SELECT command format: CLA INS P1 P2 Lc AID
        if (apdu.size < 5) {
            Log.w(TAG, "SELECT command too short")
            return STATUS_FAILED
        }

        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) {
            Log.w(TAG, "SELECT command length mismatch")
            return STATUS_FAILED
        }

        val aid = apdu.copyOfRange(5, 5 + lc)
        
        if (aid.contentEquals(AID_MDL)) {
            isSelected = true
            dataOffset = 0
            Log.i(TAG, "mDL application selected")
            return STATUS_SUCCESS
        } else {
            isSelected = false
            Log.w(TAG, "Unknown AID: ${aid.toHexString()}")
            return STATUS_FILE_NOT_FOUND
        }
    }

    private fun handleEnvelopeCommand(apdu: ByteArray): ByteArray {
        if (!isSelected) {
            Log.w(TAG, "ENVELOPE called without SELECT")
            return STATUS_FAILED
        }

        if (mdocData == null || mdocData!!.isEmpty()) {
            Log.w(TAG, "No mDoc data available")
            return STATUS_FILE_NOT_FOUND
        }

        // Return the complete mDoc data with success status
        Log.i(TAG, "Sending mDoc data: ${mdocData!!.size} bytes")
        return mdocData!! + STATUS_SUCCESS
    }

    private fun handleReadBinaryCommand(apdu: ByteArray): ByteArray {
        if (!isSelected) {
            Log.w(TAG, "READ BINARY called without SELECT")
            return STATUS_FAILED
        }

        if (mdocData == null || mdocData!!.isEmpty()) {
            Log.w(TAG, "No mDoc data available")
            return STATUS_FILE_NOT_FOUND
        }

        // P1 P2 represent offset (optional implementation for chunked reading)
        val offset = if (apdu.size >= 4) {
            ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        } else {
            0
        }

        val le = if (apdu.size >= 5) (apdu[4].toInt() and 0xFF) else 256
        val maxLen = minOf(le, 256)

        return if (offset < mdocData!!.size) {
            val endOffset = minOf(offset + maxLen, mdocData!!.size)
            val chunk = mdocData!!.copyOfRange(offset, endOffset)
            Log.d(TAG, "Sending chunk: offset=$offset, length=${chunk.size}")
            chunk + STATUS_SUCCESS
        } else {
            Log.w(TAG, "Read beyond data size")
            STATUS_SUCCESS // End of file
        }
    }

    override fun onDeactivated(reason: Int) {
        val reasonStr = when (reason) {
            DEACTIVATION_LINK_LOSS -> "Link Lost"
            DEACTIVATION_DESELECTED -> "Deselected"
            else -> "Unknown ($reason)"
        }
        Log.i(TAG, "HCE deactivated: $reasonStr")
        isSelected = false
        dataOffset = 0
    }

    // Helper extension functions
    private fun Byte.toHex(): String = String.format("0x%02X", this)
    
    private fun ByteArray.toHexString(): String = 
        joinToString(" ") { String.format("%02X", it) }
}
