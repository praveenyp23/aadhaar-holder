package com.example.mdoc.common

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import java.io.IOException
import java.nio.charset.Charset

object NfcHelper {
    
    private const val MIME_TYPE = "application/vnd.iso.18013-5"
    
    fun createMdocNdefMessage(mdocBase64: String): NdefMessage {
        val mimeBytes = MIME_TYPE.toByteArray(Charset.forName("UTF-8"))
        val dataBytes = mdocBase64.toByteArray(Charset.forName("UTF-8"))
        
        val mimeRecord = NdefRecord(
            NdefRecord.TNF_MIME_MEDIA,
            mimeBytes,
            ByteArray(0),
            dataBytes
        )
        
        return NdefMessage(arrayOf(mimeRecord))
    }
    
    fun writeNdefMessageToTag(tag: Tag, ndefMessage: NdefMessage): Boolean {
        return try {
            val ndef = Ndef.get(tag)
            if (ndef != null) {
                ndef.connect()
                
                if (!ndef.isWritable) {
                    ndef.close()
                    return false
                }
                
                if (ndef.maxSize < ndefMessage.toByteArray().size) {
                    ndef.close()
                    return false
                }
                
                ndef.writeNdefMessage(ndefMessage)
                ndef.close()
                true
            } else {
                val ndefFormatable = NdefFormatable.get(tag)
                if (ndefFormatable != null) {
                    try {
                        ndefFormatable.connect()
                        ndefFormatable.format(ndefMessage)
                        ndefFormatable.close()
                        true
                    } catch (e: IOException) {
                        false
                    }
                } else {
                    false
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
    
    fun readMdocFromNdefMessage(ndefMessage: NdefMessage): String? {
        for (record in ndefMessage.records) {
            if (record.tnf == NdefRecord.TNF_MIME_MEDIA) {
                val mimeType = String(record.type, Charset.forName("UTF-8"))
                if (mimeType == MIME_TYPE) {
                    return String(record.payload, Charset.forName("UTF-8"))
                }
            }
        }
        return null
    }
    
    fun readMdocFromTag(tag: Tag): String? {
        return try {
            val ndef = Ndef.get(tag)
            if (ndef != null) {
                ndef.connect()
                val ndefMessage = ndef.ndefMessage
                ndef.close()
                if (ndefMessage != null) {
                    readMdocFromNdefMessage(ndefMessage)
                } else {
                    null
                }
            } else {
                null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
