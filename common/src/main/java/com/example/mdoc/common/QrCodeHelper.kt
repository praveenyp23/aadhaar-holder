package com.example.mdoc.common

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.google.gson.Gson

data class DeviceEngagement(
    val bleServiceUuid: String,
    val bleAddress: String,
    val timestamp: Long = System.currentTimeMillis()
)

object QrCodeHelper {

    /**
     * Generate a proper ISO 18013-5 QR code containing a CBOR-encoded Device Engagement
     * with `mdoc:` URI scheme for use with multipaz-identity-reader.
     */
    fun generateIso18013QrCode(engagementUri: String, size: Int = 512): Bitmap {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(engagementUri, BarcodeFormat.QR_CODE, size, size)
        val w = bitMatrix.width
        val h = bitMatrix.height
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565)
        for (x in 0 until w) for (y in 0 until h)
            bmp.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
        return bmp
    }

    // ── Legacy helpers (kept for backward compat) ────────────────────

    fun generateQrCodeForBle(bleAddress: String): Bitmap {
        val engagement = DeviceEngagement(
            bleServiceUuid = BleConstants.SERVICE_UUID.toString(),
            bleAddress = bleAddress
        )
        
        val json = Gson().toJson(engagement)
        
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(json, BarcodeFormat.QR_CODE, 512, 512)
        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
        
        return bitmap
    }
    
    fun parseDeviceEngagement(qrCodeData: String): DeviceEngagement? {
        return try {
            Gson().fromJson(qrCodeData, DeviceEngagement::class.java)
        } catch (e: Exception) {
            null
        }
    }
}
