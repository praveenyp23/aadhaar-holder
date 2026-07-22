package com.example.mdoc.holder

import android.app.Activity
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.util.Log
import android.widget.Toast

/**
 * Activity that handles NFC engagement and presentation.
 * This activity is launched when an NFC tap is detected.
 * It manages the NFC device engagement and initiates credential presentation.
 */
class NfcActivity : Activity() {
    
    private var mdocBase64: String = ""
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        Log.d("MDOC_NFC", "NfcActivity launched")
        
        try {
            loadMdocCredential()
            
            val intent = intent
            if (intent != null) {
                handleNfcIntent(intent)
            }
        } catch (e: Exception) {
            Log.e("MDOC_NFC", "NFC engagement failed", e)
            Toast.makeText(this, "NFC engagement failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
        
        finish()
    }
    
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) {
            handleNfcIntent(intent)
        }
    }
    
    private fun loadMdocCredential() {
        try {
            mdocBase64 = assets.open("mdoc_b64.txt").bufferedReader().use { it.readText().trim() }
            Log.d("MDOC_NFC", "Credential loaded: ${mdocBase64.length} bytes")
        } catch (e: Exception) {
            Log.e("MDOC_NFC", "Error loading credential", e)
        }
    }
    
    private fun handleNfcIntent(intent: android.content.Intent) {
        val action = intent.action
        
        if (NfcAdapter.ACTION_TAG_DISCOVERED == action ||
            NfcAdapter.ACTION_NDEF_DISCOVERED == action) {
            
            Log.d("MDOC_NFC", "NFC tag detected, action: $action")
            
            val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            if (tag != null && mdocBase64.isNotEmpty()) {
                try {
                    // In a full implementation, this would:
                    // 1. Parse the engagement request from the tag
                    // 2. Initialize the presentation session
                    // 3. Handle any authentication needed
                    
                    val ndefMessage = com.example.mdoc.common.NfcHelper.createMdocNdefMessage(mdocBase64)
                    val success = com.example.mdoc.common.NfcHelper.writeNdefMessageToTag(tag, ndefMessage)
                    
                    Log.d("MDOC_NFC", "Credential transfer via NFC: $success")
                    
                    if (success) {
                        Toast.makeText(this, "Credential shared successfully", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, "Share incomplete. Try again.", Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    Log.e("MDOC_NFC", "NFC operation failed", e)
                    Toast.makeText(this, "Transfer failed. Try again.", Toast.LENGTH_SHORT).show()
                }
            } else {
                Log.w("MDOC_NFC", "No tag found or credential not loaded")
            }
        }
    }
}
