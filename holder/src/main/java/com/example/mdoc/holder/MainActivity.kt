package com.example.mdoc.holder

import android.Manifest
import android.app.PendingIntent
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.content.IntentFilter
import android.graphics.BitmapFactory
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.cardemulation.CardEmulation
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import com.example.mdoc.holder.ui.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.app.ActivityCompat
import com.example.mdoc.common.BleTransferManager
import com.example.mdoc.common.CredentialDownloadService
import com.example.mdoc.common.Iso18013BleServer
import com.example.mdoc.common.Iso18013Crypto
import com.example.mdoc.common.MdocCardData
import com.example.mdoc.common.MdocCardExtractor
import com.example.mdoc.common.NdefHandoverBuilder
import com.example.mdoc.common.NfcHelper
import com.example.mdoc.common.OpenId4VpZkClient
import com.example.mdoc.common.QrCodeHelper
import com.example.mdoc.common.ZkPresentationManager
import com.example.mdoc.holder.MdocFieldExtractor
import android.content.pm.PackageManager
import android.widget.Toast
import com.mdocholder.app.R
import androidx.lifecycle.lifecycleScope
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.Array as CborArray
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.security.KeyPair
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import androidx.compose.ui.res.painterResource

class MainActivity : ComponentActivity() {

    companion object {
        private const val REQUEST_BLUETOOTH = 1001
        private const val TAG = "MDOC_HOLDER"
        const val MDOC_FILE = "aadhaar_mdoc_b64.txt"
    }

    private var nfcAdapter: NfcAdapter? = null
    private var bleTransferManager: BleTransferManager? = null
    private var iso18013BleServer: Iso18013BleServer? = null
    private var mdocBase64: String = ""
    private var mdocBytes: ByteArray? = null
    private var extractedFields: Map<String, String> = emptyMap()
    private var docTypeExtracted: String = ""

    // Mutable state for Compose UI
    private var _presentationStatus = mutableStateOf("")
    private var _showPresentationDialog = mutableStateOf(false)
    private var _credentialLoaded = mutableStateOf(false)
    private var _downloadStatus = mutableStateOf("")
    private var _isDownloading = mutableStateOf(false)
    private var iacaCertPem: String = ""

    private val credentialDownloadService = CredentialDownloadService()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        try {
            bleTransferManager = BleTransferManager(this)
        } catch (e: Exception) {
            Log.e(TAG, "BLE Transfer Manager init failed", e)
            bleTransferManager = null
        }
        try {
            iso18013BleServer = Iso18013BleServer(this)
        } catch (e: Exception) {
            Log.e(TAG, "ISO 18013 BLE server init failed", e)
            iso18013BleServer = null
        }

        // Load IACA certificate from raw resources
        try {
            iacaCertPem = resources.openRawResource(R.raw.uidai_iaca_cert).bufferedReader().readText()
            Log.d(TAG, "IACA cert loaded: ${iacaCertPem.length} chars")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load IACA cert", e)
        }

        requestBluetoothPermissionsIfNeeded()

        // Initialize Multipaz app context for the W3C Digital Credentials API provider.
        DcApiManager.initContext(applicationContext)

        setContent {
            val presentationStatus by _presentationStatus
            val showPresentationDialog by _showPresentationDialog
            val credentialLoaded by _credentialLoaded
            val downloadStatus by _downloadStatus
            val isDownloading by _isDownloading

            HolderAppWithPermissions(
                mdocBase64 = mdocBase64,
                extractedFields = extractedFields,
                docTypeExtracted = docTypeExtracted,
                credentialLoaded = credentialLoaded,
                onLoadExistingCredential = { /* removed: no bundled/pre-downloaded credential — download only */ },
                onDownloadCredential = { uid -> downloadCredential(uid) },
                downloadStatus = downloadStatus,
                isDownloading = isDownloading,
                onBackToSourceScreen = { _credentialLoaded.value = false },
                onNfcTransferRequested = { startNfcPlusBlePresentation() },
                onBleTransferRequested = { startQrPlusBlePresentation() },
                onZkBlePresentation = { selected -> startZkBlePresentation(selected) },
                onZkScanResult = { qrText, _ ->
                    val intent = if (qrText.trim().startsWith("OPENID4VP://connect", ignoreCase = true)) {
                        // Offline OpenID4VP-over-BLE engagement.
                        Intent(this, BleClientActivity::class.java).putExtra(BleClientActivity.EXTRA_URI, qrText)
                    } else {
                        Intent(this, OpenId4VpActivity::class.java).putExtra(OpenId4VpActivity.EXTRA_URI, qrText)
                    }
                    startActivity(intent)
                },
                onZkNfc = { enableZkNfcReader() },
                mdocBytes = mdocBytes,
                iacaCertPem = iacaCertPem,
                presentationStatus = presentationStatus,
                showPresentationDialog = showPresentationDialog,
                onDismissPresentationDialog = {
                    _showPresentationDialog.value = false
                    iso18013BleServer?.stop()
                }
            )
        }
    }

    override fun onResume() {
        super.onResume()
        // Set our NdefService as preferred so the NDEF AID routes to us
        try {
            val cardEmulation = CardEmulation.getInstance(nfcAdapter)
            cardEmulation?.setPreferredService(this, ComponentName(this, NdefService::class.java))
            Log.d(TAG, "NdefService set as preferred HCE service")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to set preferred NFC service", e)
        }
        // Intercept all NFC intents in this Activity so Android doesn't restart us
        try {
            val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            val pi = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
            nfcAdapter?.enableForegroundDispatch(this, pi, null, null)
            Log.d(TAG, "NFC foreground dispatch enabled")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to enable foreground dispatch", e)
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            nfcAdapter?.disableForegroundDispatch(this)
        } catch (_: Exception) {}
        try {
            val cardEmulation = CardEmulation.getInstance(nfcAdapter)
            cardEmulation?.unsetPreferredService(this)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unset preferred NFC service", e)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Log.d(TAG, "onNewIntent: action=${intent.action} — absorbed, no restart")
    }

    override fun onDestroy() {
        super.onDestroy()
        iso18013BleServer?.stop()
    }

    private fun downloadCredential(uid: String) {
        _isDownloading.value = true
        _downloadStatus.value = "Downloading Aadhaar…"
        lifecycleScope.launch {
            val result = credentialDownloadService.downloadCredential(uid)
            val b64 = result.mdocBase64
            if (result.success && b64 != null) {
                // Success: the freshly-generated device key and this credential are bound together.
                mdocBase64 = b64
                mdocBytes = Base64.decode(b64, Base64.DEFAULT)
                extractFieldsSync()
                _credentialLoaded.value = true
                _downloadStatus.value = "Aadhaar downloaded successfully!"
                persistMdoc()
                registerDcApi()
            } else {
                // Failure may have already replaced the device key, so any previously-loaded
                // credential is now orphaned — clear it so the ZK flow can't hit a key mismatch.
                clearCredential()
                _downloadStatus.value = "Download failed: ${result.error}"
            }
            _isDownloading.value = false
        }
    }

    /** Persists the credential so [ZkPresentmentActivity] (launched by the verifier app) can load it. */
    private fun persistMdoc() {
        val b64 = mdocBase64
        if (b64.isEmpty()) return
        runCatching { java.io.File(filesDir, MDOC_FILE).writeText(b64) }
            .onFailure { Log.e(TAG, "persistMdoc failed", it) }
    }

    /** Imports the loaded credential into Multipaz's store and registers it for the DC API. */
    private fun registerDcApi() {
        // DISABLED. Multipaz's DC-API import adopts our shared device key (mdoc_device_key) into a
        // managed document, and its "re-import cleanly" step (store.deleteDocument) then DELETES that
        // keystore key — wiping the key the ZK and ISO 18013-5 flows depend on ("Device key not found"
        // seconds after every download). DC API is also blocked on this device's GMS matcher (WASI),
        // so registration serves no purpose here. Leave it off until DC API uses a separate key.
        Log.d(TAG, "DC API registration intentionally disabled (would delete the shared device key)")
    }

    private fun requestBluetoothPermissionsIfNeeded() {
        val perms = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        val need = perms.any { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (need) ActivityCompat.requestPermissions(this, perms, REQUEST_BLUETOOTH)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    /** Clears any loaded/persisted credential (used when a download fails, so no stale credential
     *  whose device key was just replaced can linger and cause a key mismatch). */
    private fun clearCredential() {
        mdocBase64 = ""
        mdocBytes = null
        _credentialLoaded.value = false
        runCatching { java.io.File(filesDir, MDOC_FILE).delete() }
    }

    private fun extractFieldsSync() {
        if (mdocBase64.isEmpty()) return
        try {
            val (docType, fields) = MdocFieldExtractor.extractAllFields(mdocBase64)
            docTypeExtracted = docType
            extractedFields = fields
        } catch (e: Exception) {
            Log.e(TAG, "Field extraction error", e)
        }
    }

    // ── ISO 18013-5 QR + BLE Presentation ─────────────────────────────

    private fun loadDeviceKeyPair(): KeyPair {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val alias = CredentialDownloadService.DEVICE_KEY_ALIAS
        val entry = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("No device key in KeyStore (alias=$alias). Download a credential first.")
        return KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    private fun startQrPlusBlePresentation(): android.graphics.Bitmap? {
        val mdoc = mdocBytes ?: run {
            Toast.makeText(this, "No Aadhaar loaded", Toast.LENGTH_SHORT).show()
            return null
        }
        try {
            // 1. Load MSO device key from KeyStore (same key whose public part is in MSO)
            val keyPair = loadDeviceKeyPair()
            val eDeviceKeyPub = keyPair.public as ECPublicKey
            Log.d(TAG, "Loaded MSO device key from KeyStore for presentation")

            // 2. Build Device Engagement
            val bleUuid = Iso18013BleServer.SERVICE_UUID
            val encodedDE = Iso18013Crypto.buildDeviceEngagement(eDeviceKeyPub, bleUuid)

            // 3. Extract docType from mdoc
            val docType = Iso18013Crypto.extractDocType(mdoc).ifEmpty { docTypeExtracted }
            Log.d(TAG, "BLE presentation docType='$docType' (extractDocType result, docTypeExtracted='$docTypeExtracted')")

            // 4. Prepare BLE server (handover = null for QR engagement)
            iso18013BleServer?.apply {
                stop()
                prepare(keyPair, encodedDE, mdoc, docType, handover = null)
                onStatusUpdate = { msg -> runOnUiThread { _presentationStatus.value = msg } }
                onPresentationComplete = { success, msg ->
                    runOnUiThread {
                        _presentationStatus.value = if (success) "Presentation complete!" else "Failed: $msg"
                    }
                }
                startAdvertising()
            }

            // 5. Generate QR code with mdoc: URI
            val uri = Iso18013Crypto.buildQrEngagementUri(encodedDE)
            Log.d(TAG, "QR URI: $uri (${uri.length} chars)")

            _presentationStatus.value = "Scan QR code with multipaz reader"
            _showPresentationDialog.value = true

            return QrCodeHelper.generateIso18013QrCode(uri)
        } catch (e: Exception) {
            Log.e(TAG, "QR+BLE presentation start failed", e)
            Toast.makeText(this, "Presentation failed: ${e.message}", Toast.LENGTH_LONG).show()
            return null
        }
    }

    // ── ISO 18013-5 NFC + BLE Presentation ────────────────────────────

    private fun startNfcPlusBlePresentation() {
        val mdoc = mdocBytes ?: run {
            Toast.makeText(this, "No Aadhaar loaded", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            // 1. Load MSO device key from KeyStore
            val keyPair = loadDeviceKeyPair()
            val eDeviceKeyPub = keyPair.public as ECPublicKey
            Log.d(TAG, "Loaded MSO device key from KeyStore for NFC presentation")

            // 2. Build Device Engagement
            val bleUuid = Iso18013BleServer.SERVICE_UUID
            val encodedDE = Iso18013Crypto.buildDeviceEngagement(eDeviceKeyPub, bleUuid)

            // 3. Build NDEF Handover Select message
            val handoverResult = NdefHandoverBuilder.buildStaticHandover(encodedDE, bleUuid)

            // 4. Build session transcript handover: [handoverSelectPayload, null]
            val handoverCbor = CborArray()
            handoverCbor.add(co.nstant.`in`.cbor.model.ByteString(handoverResult.handoverSelectPayload))
            handoverCbor.add(SimpleValue.NULL)

            // 5. Configure NFC service with the NDEF data
            NdefService.ndefFileContent = handoverResult.ndefMessageBytes
            NdefService.handoverPayload = handoverResult.handoverSelectPayload

            // 6. Extract docType
            val docType = Iso18013Crypto.extractDocType(mdoc).ifEmpty { docTypeExtracted }

            // 7. Prepare and start BLE server
            iso18013BleServer?.apply {
                stop()
                prepare(keyPair, encodedDE, mdoc, docType, handover = handoverCbor)
                onStatusUpdate = { msg -> runOnUiThread { _presentationStatus.value = msg } }
                onPresentationComplete = { success, msg ->
                    runOnUiThread {
                        _presentationStatus.value = if (success) "Presentation complete!" else "Failed: $msg"
                    }
                }
                startAdvertising()
            }

            _presentationStatus.value = "Tap the reader to present your Aadhaar"
            _showPresentationDialog.value = true

            Toast.makeText(this, "NFC ready – tap the multipaz reader!", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Log.e(TAG, "NFC+BLE presentation failed", e)
            Toast.makeText(this, "Presentation failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ── NFC engagement → BLE handoff (read the verifier's OPENID4VP://connect over NFC) ──

    /** Enables NFC reader mode so the user can tap the verifier and start the BLE flow. */
    fun enableZkNfcReader() {
        try {
            nfcAdapter?.enableReaderMode(
                this, { tag -> readVerifierNfc(tag) },
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null
            )
            runOnUiThread { Toast.makeText(this, "Tap the verifier phone", Toast.LENGTH_SHORT).show() }
        } catch (e: Exception) {
            Log.e(TAG, "reader mode failed", e)
        }
    }

    private fun readVerifierNfc(tag: android.nfc.Tag) {
        Log.d(TAG, "NFC tag detected, techs=${tag.techList.joinToString()}")
        val iso = android.nfc.tech.IsoDep.get(tag)
        if (iso == null) {
            Log.e(TAG, "tag is not IsoDep")
            runOnUiThread { Toast.makeText(this, "Tap didn't read. Hold the phones together and try again.", Toast.LENGTH_LONG).show() }
            return
        }
        try {
            iso.connect()
            iso.timeout = 3000
            iso.transceive(hexBytes("00A4040006F04D444F4356"))     // SELECT our engagement app (proprietary AID)
            iso.transceive(hexBytes("00A4000C02E104"))             // SELECT NDEF file
            val nlen = iso.transceive(hexBytes("00B0000002"))       // read length
            val len = ((nlen[0].toInt() and 0xFF) shl 8) or (nlen[1].toInt() and 0xFF)
            val resp = iso.transceive(hexBytes("00B00002" + "%02X".format(len.coerceAtMost(0xFF))))
            iso.close()
            val url = parseNdefUri(resp)
            Log.d(TAG, "NFC read url=$url (nlen=$len, respLen=${resp.size})")
            if (url != null && url.startsWith("OPENID4VP://connect", ignoreCase = true)) {
                nfcAdapter?.disableReaderMode(this)
                runOnUiThread {
                    Toast.makeText(this, "Verifier found — connecting", Toast.LENGTH_SHORT).show()
                    startActivity(Intent(this, BleClientActivity::class.java)
                        .putExtra(BleClientActivity.EXTRA_URI, url))
                }
            } else {
                runOnUiThread { Toast.makeText(this, "Tapped, but no request found. Make sure the verifier is on NFC (tap) mode.", Toast.LENGTH_LONG).show() }
            }
        } catch (e: Exception) {
            Log.e(TAG, "NFC read failed", e)
            runOnUiThread { Toast.makeText(this, "Tap read failed: ${e.message}. Try again.", Toast.LENGTH_LONG).show() }
        }
    }

    /** Extracts the URL from an NDEF URI record (response includes a trailing 9000). */
    private fun parseNdefUri(resp: ByteArray): String? {
        if (resp.size < 6) return null
        val msg = resp.copyOfRange(0, resp.size - 2) // strip status word
        // record: header(1) typeLen(1) payloadLen(1) type('U') payload[0x00 + url]
        var i = 0
        i += 1 // header
        val typeLen = msg[i].toInt() and 0xFF; i += 1
        val payloadLen = msg[i].toInt() and 0xFF; i += 1
        i += typeLen // skip type ('U')
        if (i >= msg.size || payloadLen < 1) return null
        // payload[0] = URI abbreviation code (0x00 = none)
        val urlBytes = msg.copyOfRange(i + 1, minOf(i + payloadLen, msg.size))
        return String(urlBytes)
    }

    private fun hexBytes(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    // ── Zero-Knowledge presentation ───────────────────────────────────

    /**
     * Starts a ZK presentation over BLE (QR engagement): same transport as [startQrPlusBlePresentation]
     * but the holder responds with a longfellow proof of only [selected] attributes. The returned QR
     * is the device-engagement QR for a ZK-capable reader (e.g. Multipaz Identity Reader) to scan.
     */
    private fun startZkBlePresentation(
        selected: List<ZkPresentationManager.AttributeRef>
    ): android.graphics.Bitmap? {
        val mdoc = mdocBytes ?: run {
            Toast.makeText(this, "No Aadhaar loaded", Toast.LENGTH_SHORT).show(); return null
        }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Select at least one attribute", Toast.LENGTH_SHORT).show(); return null
        }
        try {
            val keyPair = loadDeviceKeyPair()
            val eDeviceKeyPub = keyPair.public as ECPublicKey
            val bleUuid = Iso18013BleServer.SERVICE_UUID
            val encodedDE = Iso18013Crypto.buildDeviceEngagement(eDeviceKeyPub, bleUuid)
            val docType = Iso18013Crypto.extractDocType(mdoc).ifEmpty { docTypeExtracted }

            iso18013BleServer?.apply {
                stop()
                prepare(keyPair, encodedDE, mdoc, docType, handover = null)
                enableZkMode(selected)
                onStatusUpdate = { msg -> runOnUiThread { _presentationStatus.value = msg } }
                onPresentationComplete = { success, msg ->
                    runOnUiThread {
                        _presentationStatus.value = if (success) "ZK presentation complete!" else "Failed: $msg"
                    }
                }
                startAdvertising()
            }

            val uri = Iso18013Crypto.buildQrEngagementUri(encodedDE)
            _presentationStatus.value = "Scan with a ZK-capable reader (${selected.size} attr)"
            _showPresentationDialog.value = true
            return QrCodeHelper.generateIso18013QrCode(uri)
        } catch (e: Exception) {
            Log.e(TAG, "ZK BLE presentation failed", e)
            Toast.makeText(this, "ZK presentation failed: ${e.message}", Toast.LENGTH_LONG).show()
            return null
        }
    }

    /**
     * Presents a ZK proof of [selected] attributes online via OpenID4VP — to the OWF Multipaz verifier
     * (verifier.multipaz.org) or any compatible verifier, given its scanned [qrText].
     */
    private fun presentZkOverOpenId4Vp(
        qrText: String,
        selected: List<ZkPresentationManager.AttributeRef>
    ) {
        val mdoc = mdocBytes ?: run {
            Toast.makeText(this, "No Aadhaar loaded", Toast.LENGTH_SHORT).show(); return
        }
        if (selected.isEmpty()) {
            Toast.makeText(this, "Select at least one attribute", Toast.LENGTH_SHORT).show(); return
        }
        _presentationStatus.value = "Contacting verifier…"
        _showPresentationDialog.value = true
        lifecycleScope.launch {
            try {
                val req = OpenId4VpZkClient.fetchRequest(qrText)
                _presentationStatus.value = "Generating ZK proof for ${selected.size} attribute(s)…"
                val deviceKey = loadDeviceKeyPair().private
                val result = OpenId4VpZkClient.presentZk(req, mdoc, docTypeExtracted, selected, deviceKey)
                _presentationStatus.value = if (result.httpCode in 200..299) {
                    "ZK proof accepted by verifier ✅ (HTTP ${result.httpCode})"
                } else {
                    "Verifier returned HTTP ${result.httpCode}: ${result.body.take(160)}"
                }
            } catch (e: Exception) {
                Log.e(TAG, "ZK OpenID4VP presentation failed", e)
                _presentationStatus.value = "Failed: ${e.message}"
            }
        }
    }
}




// ── Aadhaar brand colors ──────────────────────────────────────────────
private val AadhaarBlue   = Color(0xFF003772)
private val AadhaarOrange = Color(0xFFEB7B2A)

@Composable
fun AadhaarHeader() {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        androidx.compose.foundation.Image(
            painter = painterResource(id = R.drawable.ic_aadhaar_logo),
            contentDescription = "Aadhaar logo",
            modifier = Modifier.size(110.dp)
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            "Aadhaar Holder",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            color = AadhaarBlue
        )
        Text(
            "मेरा आधार, मेरी पहचान",
            fontSize = 11.sp,
            color = AadhaarBlue.copy(alpha = 0.65f)
        )
    }
}

@Composable
fun AadhaarLogoSmall(modifier: Modifier = Modifier) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.foundation.Image(
            painter = painterResource(id = R.drawable.ic_aadhaar_logo),
            contentDescription = "Aadhaar",
            modifier = Modifier.size(22.dp)
        )
        Spacer(modifier = Modifier.width(3.dp))
        Text("AADHAAR", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = AadhaarBlue)
    }
}

@Composable
fun HolderAppWithPermissions(
    mdocBase64: String,
    extractedFields: Map<String, String>,
    docTypeExtracted: String,
    credentialLoaded: Boolean,
    onLoadExistingCredential: () -> Unit = {},
    onDownloadCredential: (String) -> Unit = {},
    downloadStatus: String = "",
    isDownloading: Boolean = false,
    onBackToSourceScreen: () -> Unit = {},
    onNfcTransferRequested: () -> Unit = {},
    onBleTransferRequested: () -> android.graphics.Bitmap? = { null },
    onZkBlePresentation: (List<ZkPresentationManager.AttributeRef>) -> android.graphics.Bitmap? = { null },
    onZkScanResult: (String, List<ZkPresentationManager.AttributeRef>) -> Unit = { _, _ -> },
    onZkNfc: () -> Unit = {},
    mdocBytes: ByteArray? = null,
    iacaCertPem: String = "",
    presentationStatus: String = "",
    showPresentationDialog: Boolean = false,
    onDismissPresentationDialog: () -> Unit = {}
) {
    var qrBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var showQrScreen by remember { mutableStateOf(false) }
    var showCredentialDetails by remember { mutableStateOf(false) }
    var transferStatus by remember { mutableStateOf("") }
    var showTransferStatus by remember { mutableStateOf(false) }

    Box(modifier = Modifier.fillMaxSize()) {
        if (!credentialLoaded) {
            // Show credential selection screen
            CredentialSourceScreen(
                onLoadExisting = onLoadExistingCredential,
                onDownload = onDownloadCredential,
                downloadStatus = downloadStatus,
                isDownloading = isDownloading
            )
        } else {
            HolderApp(
                mdocLoaded = mdocBase64.isNotEmpty(),
                extractedFields = extractedFields,
                docType = docTypeExtracted,
                onViewCredential = { showCredentialDetails = true },
                onBackToSourceScreen = onBackToSourceScreen,
                onStartNfc = onNfcTransferRequested,
                onStartBle = {
                    val bmp = onBleTransferRequested()
                    if (bmp != null) qrBitmap = bmp
                },
                onZkBle = { selected ->
                    val bmp = onZkBlePresentation(selected)
                    if (bmp != null) qrBitmap = bmp
                },
                onZkScanResult = onZkScanResult,
                onZkNfc = onZkNfc,
                mdocBytes = mdocBytes,
                iacaCertPem = iacaCertPem,
                showCredentialDetails = showCredentialDetails,
                onCredentialDetailsDismiss = { showCredentialDetails = false },
                showQrScreen = false,
                qrBitmap = null,
                onQrScreenDismiss = {},
                transferStatus = transferStatus,
                showTransferStatus = showTransferStatus,
                onTransferStatusDismiss = { showTransferStatus = false }
            )
        }

        // Show presentation dialog ON TOP of HolderApp
        if (showPresentationDialog) {
            PresentationDialog(
                status = presentationStatus,
                qrBitmap = qrBitmap,
                onDismiss = {
                    qrBitmap = null
                    showQrScreen = false
                    onDismissPresentationDialog()
                }
            )
        }
    }
}

@Composable
fun CredentialSourceScreen(
    onLoadExisting: () -> Unit,
    onDownload: (String) -> Unit,
    downloadStatus: String,
    isDownloading: Boolean
) {
    var uidInput by remember { mutableStateOf("") }

    AadhaarTheme {
        Surface(Modifier.fillMaxSize(), color = Aadhaar.Bg) {
            Column(
                modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                // Hero band
                Box(
                    Modifier.fillMaxWidth()
                        .clip(androidx.compose.foundation.shape.RoundedCornerShape(bottomStart = 28.dp, bottomEnd = 28.dp))
                        .background(androidx.compose.ui.graphics.Brush.verticalGradient(listOf(Aadhaar.Navy, Aadhaar.NavyDark)))
                        .padding(28.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                        Spacer(Modifier.height(24.dp))
                        Box(
                            Modifier.size(84.dp).clip(androidx.compose.foundation.shape.RoundedCornerShape(20.dp))
                                .background(Color.White).padding(12.dp),
                            contentAlignment = Alignment.Center
                        ) { AadhaarEmblem(size = 60) }
                        Spacer(Modifier.height(14.dp))
                        Text("Aadhaar Holder", fontSize = 26.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("मेरा आधार, मेरी पहचान", fontSize = 13.sp, color = Color.White.copy(alpha = 0.8f))
                        Spacer(Modifier.height(8.dp))
                    }
                }

                Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    OutlinedTextField(
                        value = uidInput,
                        onValueChange = { if (it.length <= 12 && it.all { c -> c.isDigit() }) uidInput = it },
                        label = { Text("Enter your UID") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        enabled = !isDownloading,
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Aadhaar.Navy, focusedLabelColor = Aadhaar.Navy
                        )
                    )
                    if (downloadStatus.isNotEmpty()) {
                        Text(
                            downloadStatus,
                            fontSize = 13.sp,
                            color = if (downloadStatus.contains("failed", ignoreCase = true)) Aadhaar.Red else Aadhaar.Green
                        )
                    }
                    if (isDownloading) {
                        LinearProgressIndicator(Modifier.fillMaxWidth(), color = Aadhaar.Saffron)
                    }
                    PrimaryButton(
                        "Download Aadhaar",
                        enabled = uidInput.length == 12 && !isDownloading
                    ) { if (uidInput.length == 12) onDownload(uidInput) }
                }
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun PresentationDialog(
    status: String,
    qrBitmap: android.graphics.Bitmap?,
    onDismiss: () -> Unit
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        // Dim background
        Box(modifier = Modifier.fillMaxSize().padding(0.dp)) {
            Surface(modifier = Modifier.fillMaxSize(), color = Color.Black.copy(alpha = 0.5f)) {}
        }
        Card(
            modifier = Modifier.padding(24.dp).fillMaxWidth(),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("ISO 18013-5 Presentation", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                if (qrBitmap != null) {
                    androidx.compose.foundation.Image(
                        bitmap = qrBitmap.asImageBitmap(),
                        contentDescription = "Device Engagement QR",
                        modifier = Modifier.size(250.dp)
                    )
                    Text("Scan with multipaz reader", fontSize = 12.sp, color = Color.Gray)
                }
                if (status.isNotEmpty()) {
                    Box(modifier = Modifier.fillMaxWidth().height(1.dp).padding(horizontal = 0.dp)
                        .then(Modifier.drawBehind { drawRect(Color.LightGray) }))
                    Text(status, fontSize = 14.sp, color = Color(0xFF1565C0))
                }
                if (!status.contains("complete", ignoreCase = true) && !status.contains("failed", ignoreCase = true)) {
                    Box(
                        modifier = Modifier.fillMaxWidth().height(4.dp).padding(top = 8.dp)
                            .then(Modifier.drawBehind { drawRect(Color(0xFF7C3AED)) })
                    )
                }
                Button(onClick = onDismiss, modifier = Modifier.padding(top = 8.dp)) {
                    Text("Close")
                }
            }
        }
    }
}

@Composable
fun HolderApp(
    mdocLoaded: Boolean,
    extractedFields: Map<String, String>,
    docType: String,
    onViewCredential: () -> Unit,
    onBackToSourceScreen: () -> Unit,
    onStartNfc: () -> Unit,
    onStartBle: () -> Unit,
    onZkBle: (List<ZkPresentationManager.AttributeRef>) -> Unit = {},
    onZkScanResult: (String, List<ZkPresentationManager.AttributeRef>) -> Unit = { _, _ -> },
    onZkNfc: () -> Unit = {},
    mdocBytes: ByteArray? = null,
    iacaCertPem: String = "",
    showCredentialDetails: Boolean,
    onCredentialDetailsDismiss: () -> Unit,
    showQrScreen: Boolean,
    qrBitmap: android.graphics.Bitmap?,
    onQrScreenDismiss: () -> Unit,
    transferStatus: String,
    showTransferStatus: Boolean,
    onTransferStatusDismiss: () -> Unit
) {
    var tab by remember { mutableStateOf(0) }

    AadhaarTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = Aadhaar.Bg) {
            when {
                showTransferStatus -> TransferStatusDialog(transferStatus, onTransferStatusDismiss)
                showCredentialDetails && mdocLoaded ->
                    FieldsDisplay(extractedFields, docType, onCredentialDetailsDismiss)
                else -> Scaffold(
                    containerColor = Aadhaar.Bg,
                    bottomBar = { AadhaarBottomNav(tab) { tab = it } }
                ) { pad ->
                    Box(Modifier.fillMaxSize().padding(pad)) {
                        when (tab) {
                            0 -> HomeTab(mdocLoaded, extractedFields, onViewCredential, onGoShare = { tab = 1 })
                            1 -> ShareTab(mdocLoaded, onZkScanResult, onZkNfc, onStartNfc, onStartBle)
                            else -> SettingsTab(mdocLoaded, mdocBytes, iacaCertPem, onBackToSourceScreen)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AadhaarBottomNav(selected: Int, onSelect: (Int) -> Unit) {
    NavigationBar(containerColor = Aadhaar.Surface) {
        val items = listOf("Home" to "⌂", "Share" to "⇪", "Settings" to "⚙")
        items.forEachIndexed { i, (label, glyph) ->
            NavigationBarItem(
                selected = selected == i,
                onClick = { onSelect(i) },
                icon = { Text(glyph, fontSize = 20.sp) },
                label = { Text(label, fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Aadhaar.Navy,
                    selectedTextColor = Aadhaar.Navy,
                    indicatorColor = Aadhaar.SaffronSoft,
                    unselectedIconColor = Aadhaar.Muted,
                    unselectedTextColor = Aadhaar.Muted
                )
            )
        }
    }
}

@Composable
private fun HomeTab(
    mdocLoaded: Boolean,
    extractedFields: Map<String, String>,
    onViewCredential: () -> Unit,
    onGoShare: () -> Unit
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        BrandTopBar("Aadhaar Holder")
        if (mdocLoaded) {
            val cardData = remember(extractedFields) { MdocCardExtractor.fromStringMap(extractedFields) }
            val frontAddress = extractedFields["address"] ?: cardData.address
            val regionalAddress = extractedFields["regional_address"] ?: extractedFields["local_address"] ?: ""
            Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    DigitalAadhaarCard(cardData, address = frontAddress, regionalAddress = regionalAddress)
                }
                Text("Swipe or tap the card to see your address", fontSize = 11.sp, color = Aadhaar.Muted)
                SectionLabel("Quick actions")
                ActionListItem("Share with a verifier", "Prove your details with zero-knowledge", "⇪", onGoShare)
                ActionListItem("View full details", "See every detail in your Aadhaar", "≡", onViewCredential)
                Spacer(Modifier.height(8.dp))
            }
        } else {
            Text("Aadhaar not loaded. Restart the app.", color = Aadhaar.Muted, fontSize = 14.sp,
                modifier = Modifier.padding(24.dp))
        }
    }
}

@Composable
private fun ShareTab(
    mdocLoaded: Boolean,
    onZkScanResult: (String, List<ZkPresentationManager.AttributeRef>) -> Unit,
    onZkNfc: () -> Unit,
    onStartNfc: () -> Unit,
    onStartBle: () -> Unit
) {
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { onZkScanResult(it, emptyList()) }
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        BrandTopBar("Share Aadhaar")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {

            // ── Zero-Knowledge ──
            ShareSection(
                title = "Zero-Knowledge Proof",
                note = "Prove just what a verifier asks for — nothing else about your Aadhaar is shared, and it's still checked as genuine."
            ) {
                PrimaryButton("Scan verifier QR") {
                    scanLauncher.launch(
                        ScanOptions().setOrientationLocked(false).setBeepEnabled(false)
                            .setPrompt("Scan the verifier's QR code")
                            .setCaptureActivity(ZkScanActivity::class.java)
                    )
                }
                PrimaryButton("Tap verifier", onClick = onZkNfc)
            }

            // ── Selective Share ──
            ShareSection(
                title = "Selective Share",
                note = "Share only the details you approve, signed by the issuer so the reader can trust they're genuine."
            ) {
                PrimaryButton("Show QR for reader", onClick = onStartBle)
                PrimaryButton("Tap reader", onClick = onStartNfc)
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun ShareSection(title: String, note: String, actions: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
        elevation = CardDefaults.cardElevation(1.dp)
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Ink)
            Row(verticalAlignment = Alignment.Top) {
                Text("ⓘ", fontSize = 14.sp, color = Aadhaar.Navy)
                Spacer(Modifier.width(8.dp))
                Text(note, fontSize = 12.sp, color = Aadhaar.Muted, lineHeight = 17.sp)
            }
            actions()
        }
    }
}

@Composable
private fun SettingsTab(
    mdocLoaded: Boolean,
    mdocBytes: ByteArray?,
    iacaCertPem: String,
    onBackToSourceScreen: () -> Unit
) {
    var iacaEnabled by remember { mutableStateOf(false) }
    var iacaResult by remember { mutableStateOf<Iso18013Crypto.IacaVerificationResult?>(null) }
    var showRaw by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        BrandTopBar("Settings")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            SectionLabel("Security")
            Card(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
                elevation = CardDefaults.cardElevation(1.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Verify issuer certificate", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Aadhaar.Ink)
                            Text("Check IACA → Document Signer → MSO chain", fontSize = 12.sp, color = Aadhaar.Muted)
                        }
                        Switch(checked = iacaEnabled, onCheckedChange = { iacaEnabled = it; if (!it) iacaResult = null })
                    }
                    if (iacaEnabled && mdocBytes != null && iacaCertPem.isNotEmpty()) {
                        PrimaryButton("Run verification") { iacaResult = Iso18013Crypto.verifyIacaCertChain(mdocBytes, iacaCertPem) }
                        iacaResult?.let { r ->
                            Card(colors = CardDefaults.cardColors(containerColor = if (r.success) Aadhaar.GreenSoft else Color(0xFFFFEBEE))) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(if (r.success) "Passed" else "Failed", fontWeight = FontWeight.Bold,
                                        color = if (r.success) Aadhaar.Green else Aadhaar.Red)
                                    Text(r.message, fontSize = 12.sp, color = Aadhaar.Muted)
                                }
                            }
                        }
                    } else if (iacaEnabled) {
                        Text("Aadhaar or issuer certificate unavailable.", fontSize = 12.sp, color = Aadhaar.Muted)
                    }
                }
            }

            SectionLabel("Developer")
            OutlineActionButton("Show raw Aadhaar (Base64)") { showRaw = true }

            SectionLabel("Aadhaar")
            OutlineActionButton("Switch / re-download Aadhaar", onClick = onBackToSourceScreen)
            Spacer(Modifier.height(8.dp))
        }
    }
    if (showRaw && mdocBytes != null) {
        RawCredentialDialog(
            base64 = android.util.Base64.encodeToString(mdocBytes, android.util.Base64.NO_WRAP),
            onDismiss = { showRaw = false }
        )
    }
}

@Composable
fun MainScreen(
    mdocLoaded: Boolean,
    extractedFields: Map<String, String>,
    onViewCredential: () -> Unit,
    onBackToSourceScreen: () -> Unit,
    onStartNfc: () -> Unit,
    onStartBle: () -> Unit,
    mdocBytes: ByteArray? = null,
    iacaCertPem: String = ""
) {
    var iacaCheckEnabled by remember { mutableStateOf(false) }
    var iacaResult by remember { mutableStateOf<Iso18013Crypto.IacaVerificationResult?>(null) }
    var showRawDialog by remember { mutableStateOf(false) }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(top = 48.dp, start = 24.dp, end = 24.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.foundation.Image(
                    painter = painterResource(id = R.drawable.ic_aadhaar_logo),
                    contentDescription = "Aadhaar",
                    modifier = Modifier.size(38.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "Aadhaar Holder",
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold,
                    color = AadhaarBlue
                )
            }

        if (mdocLoaded) {
            // Show Raw Credential Button
            Button(
                onClick = { showRawDialog = true },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF263238))
            ) {
                Text("Show Raw Credential (Base64)")
            }
            val cardData = remember(extractedFields) { MdocCardExtractor.fromStringMap(extractedFields) }
            CredentialCardView(cardData = cardData)

            Button(onClick = onViewCredential, modifier = Modifier.fillMaxWidth()) {
                Text("Details")
            }

            Box(modifier = Modifier.fillMaxWidth().height(1.dp).padding(vertical = 8.dp)
                .then(Modifier.drawBehind { drawRect(Color.LightGray) }))

            Text("Present to multipaz reader", fontSize = 16.sp, fontWeight = FontWeight.Bold)

            Button(
                onClick = onStartNfc,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C3AED))
            ) {
                Text("Tap Reader")
            }

            Button(
                onClick = onStartBle,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C3AED))
            ) {
                Text("Scan QR")
            }

            Spacer(modifier = Modifier.height(16.dp))

            // IACA Verification Section
            Box(modifier = Modifier.fillMaxWidth().height(1.dp)
                .then(Modifier.drawBehind { drawRect(Color.LightGray) }))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("IACA Cert Verification", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                Switch(
                    checked = iacaCheckEnabled,
                    onCheckedChange = { iacaCheckEnabled = it; if (!it) iacaResult = null }
                )
            }

            if (iacaCheckEnabled && mdocBytes != null && iacaCertPem.isNotEmpty()) {
                Button(
                    onClick = {
                        iacaResult = Iso18013Crypto.verifyIacaCertChain(mdocBytes, iacaCertPem)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF0D47A1)
                    )
                ) {
                    Text("Verify IACA → DocSigner → MSO")
                }

                iacaResult?.let { result ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = if (result.success) Color(0xFFE8F5E9) else Color(0xFFFFEBEE)
                        )
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                if (result.success) "✅ PASSED" else "❌ FAILED",
                                fontWeight = FontWeight.Bold,
                                fontSize = 16.sp,
                                color = if (result.success) Color(0xFF2E7D32) else Color(0xFFC62828)
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(result.message, fontSize = 12.sp)
                            result.iacaSubject?.let {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("IACA: $it", fontSize = 10.sp, color = Color.Gray)
                            }
                            result.docSignerSubject?.let {
                                Text("DocSigner: $it", fontSize = 10.sp, color = Color.Gray)
                            }
                        }
                    }
                }
            } else if (iacaCheckEnabled) {
                Text("Credential or IACA cert not available", fontSize = 12.sp, color = Color.Gray)
            }

            Button(
                onClick = onBackToSourceScreen,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Gray)
            ) {
                Text("Back to Credential Selection")
            }
        } else {
            Text("Credential not loaded. Restart the app.", color = Color.Gray, fontSize = 14.sp)
        }

        if (showRawDialog && mdocBytes != null) {
            RawCredentialDialog(
                base64 = android.util.Base64.encodeToString(mdocBytes, android.util.Base64.NO_WRAP),
                onDismiss = { showRawDialog = false }
            )
        }

        } // closes Column

        // Aadhaar badge — top-right overlay
        AadhaarLogoSmall(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 12.dp, end = 16.dp)
        )
    } // closes Box
}

@Composable
fun ZkProofScreen(
    mdocBytes: ByteArray?,
    docType: String,
    onZkBle: (List<ZkPresentationManager.AttributeRef>) -> Unit,
    onZkScanResult: (String, List<ZkPresentationManager.AttributeRef>) -> Unit,
    onZkNfc: () -> Unit = {}
) {
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { onZkScanResult(it, emptyList()) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Spacer(Modifier.height(8.dp))
        Text("Share with a verifier", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = AadhaarBlue)
        Text(
            "Scan the verifier's QR code, or tap the verifier with your phone. You'll see exactly " +
                "what's requested and can approve or cancel.",
            fontSize = 13.sp, color = Color(0xFF616161)
        )

        Spacer(Modifier.height(8.dp))
        Button(
            onClick = {
                scanLauncher.launch(
                    ScanOptions().setOrientationLocked(false).setBeepEnabled(false)
                        .setPrompt("Scan the verifier's QR code")
                        .setCaptureActivity(ZkScanActivity::class.java)
                )
            },
            modifier = Modifier.fillMaxWidth().height(52.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00796B))
        ) { Text("Scan verifier QR", fontSize = 16.sp) }

        Button(
            onClick = onZkNfc,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AadhaarBlue)
        ) { Text("Tap verifier (NFC)", fontSize = 16.sp) }
    }
}

@Composable
fun CredentialCardView(cardData: MdocCardData) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFAFAFA)),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            cardData.residentImageBytes?.let { bytes ->
                val bitmap = remember(bytes) {
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                }
                if (bitmap != null) {
                    androidx.compose.foundation.Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier.size(80.dp),
                        contentScale = ContentScale.Crop
                    )
                    Spacer(modifier = Modifier.width(16.dp))
                }
            }
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                if (cardData.name.isNotBlank()) Text(cardData.name, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF212121))
                if (cardData.dateOfBirth.isNotBlank()) Text(cardData.dateOfBirth, fontSize = 13.sp, color = Color(0xFF616161))
                if (cardData.gender.isNotBlank()) Text(cardData.gender, fontSize = 13.sp, color = Color(0xFF616161))
                if (cardData.address.isNotBlank()) Text(cardData.address, fontSize = 12.sp, color = Color(0xFF757575), maxLines = 2)
            }
        }
    }
}

@Composable
fun FieldsDisplay(
    fields: Map<String, String>,
    docType: String,
    onDismiss: () -> Unit
) {
    fun humanize(k: String) = k.split("_").joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
        .replace(Regex("(?<=[A-Za-z])(?=[0-9])"), " ")
    AadhaarTheme {
        Surface(Modifier.fillMaxSize(), color = Aadhaar.Bg) {
            Column(Modifier.fillMaxSize()) {
                Box(
                    Modifier.fillMaxWidth()
                        .clip(androidx.compose.foundation.shape.RoundedCornerShape(bottomStart = 24.dp, bottomEnd = 24.dp))
                        .background(androidx.compose.ui.graphics.Brush.verticalGradient(listOf(Aadhaar.Navy, Aadhaar.NavyDark)))
                        .padding(20.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("‹", fontSize = 30.sp, color = Color.White, modifier = Modifier.clickable { onDismiss() })
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text("Aadhaar details", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                            Text("${fields.size} attributes", color = Color.White.copy(alpha = 0.75f), fontSize = 12.sp)
                        }
                    }
                }
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
                    contentPadding = PaddingValues(vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    val entries = fields.entries.toList()
                    items(entries.size) { index ->
                        val entry = entries[index]
                        if (entry.key == "resident_image") {
                            Card(
                                Modifier.fillMaxWidth(),
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
                                elevation = CardDefaults.cardElevation(1.dp)
                            ) {
                                Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text("Photograph", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Muted)
                                    Spacer(Modifier.height(8.dp))
                                    val imageBitmap = remember(entry.value) {
                                        runCatching {
                                            val b = Base64.decode(entry.value, Base64.DEFAULT)
                                            BitmapFactory.decodeByteArray(b, 0, b.size)
                                        }.getOrNull()
                                    }
                                    if (imageBitmap != null) {
                                        androidx.compose.foundation.Image(
                                            bitmap = imageBitmap.asImageBitmap(),
                                            contentDescription = "Photograph",
                                            modifier = Modifier.size(160.dp)
                                                .clip(androidx.compose.foundation.shape.RoundedCornerShape(12.dp)),
                                            contentScale = ContentScale.Crop
                                        )
                                    } else {
                                        Text("Image unavailable", fontSize = 11.sp, color = Aadhaar.Muted)
                                    }
                                }
                            }
                        } else {
                            Card(
                                Modifier.fillMaxWidth(),
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
                                elevation = CardDefaults.cardElevation(1.dp)
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    Text(humanize(entry.key), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Muted)
                                    Spacer(Modifier.height(3.dp))
                                    Text(entry.value.take(200), fontSize = 15.sp, color = Aadhaar.Ink, fontWeight = FontWeight.Medium)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun QrCodeDisplay(
    qrBitmap: android.graphics.Bitmap,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Button(onClick = onDismiss, modifier = Modifier.padding(bottom = 16.dp)) {
            Text("Close QR Code")
        }
        
        androidx.compose.foundation.Image(
            bitmap = qrBitmap.asImageBitmap(),
            contentDescription = "QR Code",
            modifier = Modifier.size(300.dp)
        )
        
        Text("Scan this QR code with the reader app", fontSize = 14.sp, modifier = Modifier.padding(top = 16.dp))
    }
}

@Composable
fun TransferStatusDialog(
    statusMessage: String,
    onDismiss: () -> Unit
) {
    val safeMessage = statusMessage.ifEmpty { "Transfer in progress." }
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            Surface(modifier = Modifier.fillMaxSize(), color = Color.Black.copy(alpha = 0.5f)) {}
        }
        Card(
            modifier = Modifier.padding(24.dp).fillMaxWidth(),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text("Transfer", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Text(safeMessage, fontSize = 14.sp, modifier = Modifier.padding(8.dp))
                Box(
                    modifier = Modifier.fillMaxWidth().height(4.dp)
                        .then(Modifier.drawBehind { drawRect(Color(0xFF7C3AED)) })
                )
                Button(onClick = onDismiss) {
                    Text("OK")
                }
            }
        }
    }
}

