@file:OptIn(kotlin.time.ExperimentalTime::class)

package com.example.mdoc.holder

import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.mdoc.holder.ui.*
import androidx.lifecycle.lifecycleScope
import com.example.mdoc.common.CredentialDownloadService
import com.example.mdoc.common.ZkPresentationManager
import com.example.mdoc.common.ZkPresentationManager.SizeCheck
import com.example.mdoc.holder.ble.BleWalletClient
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.security.KeyStore

/**
 * Holder side of OpenID4VP-over-BLE. Launched from the ZK tab when an `OPENID4VP://connect` QR is
 * scanned. Connects to the verifier over BLE, shows consent for the requested (fitting) attributes,
 * generates a holder-bound longfellow ZK proof, and streams the vp_token back over BLE.
 */
class BleClientActivity : ComponentActivity() {

    companion object { const val TAG = "MDOC_BLE_CLIENT"; const val EXTRA_URI = "openid4vp_ble_uri" }

    private val brand = Color(0xFF003772)
    private var client: BleWalletClient? = null
    private var transcript: ByteArray = ByteArray(0)
    private var docType: String = ""
    private var credId: String = "aadhaar_zk"

    private sealed interface Phase {
        data class Status(val text: String) : Phase
        data class Consent(val checks: List<SizeCheck>) : Phase
        data class Presenting(val progress: Int) : Phase
        data class Done(val success: Boolean, val message: String) : Phase
    }

    private val phaseState = mutableStateOf<Phase>(Phase.Status("Starting Bluetooth"))

    private var pendingKeyHex: String? = null
    private val permLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        if (result.values.all { it }) pendingKeyHex?.let { startBle(it) }
        else phaseState.value = Phase.Done(false, "Bluetooth permission is required to share offline.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data?.toString() ?: intent.getStringExtra(EXTRA_URI)
        if (uri == null) { finish(); return }
        val keyHex = Uri.parse(uri).getQueryParameter("key")

        setContent { BleScreen(phaseState.value) }

        if (keyHex.isNullOrEmpty()) { phaseState.value = Phase.Done(false, "Invalid Bluetooth QR"); return }
        ensureBleThenStart(keyHex)
    }

    /** Requests the runtime BLE-central permissions (Android 12+), then starts. */
    private fun ensureBleThenStart(keyHex: String) {
        val perms = arrayOf(
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_CONNECT
        )
        val missing = perms.filter {
            checkSelfPermission(it) != android.content.pm.PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) startBle(keyHex)
        else { pendingKeyHex = keyHex; permLauncher.launch(missing.toTypedArray()) }
    }

    private fun startBle(verifierKeyHex: String) {
        // Pin the verifier: the signed BLE request must match this bundled certificate.
        val trustedCert = runCatching {
            resources.openRawResource(com.mdocholder.app.R.raw.verifier_cert).use {
                java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(it) as java.security.cert.X509Certificate
            }
        }.getOrNull()
        val c = BleWalletClient(
            context = this,
            verifierPublicKeyHex = verifierKeyHex,
            trustedVerifierCert = trustedCert,
            onStatus = { runOnUiThread {
                val p = phaseState.value
                if (p !is Phase.Consent && p !is Phase.Presenting) phaseState.value = Phase.Status(it)
            } },
            onProgress = { pct -> runOnUiThread {
                if (phaseState.value is Phase.Presenting) phaseState.value = Phase.Presenting(pct)
            } },
            onRequestReady = { requestJson, tr -> runOnUiThread { onRequestReady(requestJson, tr) } },
            onDone = { ok, msg -> runOnUiThread { phaseState.value = Phase.Done(ok, msg) } }
        )
        client = c
        runCatching { c.start() }.onFailure { phaseState.value = Phase.Done(false, "Bluetooth failed: ${it.message}") }
    }

    private fun onRequestReady(requestJson: String, tr: ByteArray) {
        transcript = tr
        val mdoc = loadMdoc() ?: run {
            phaseState.value = Phase.Done(false, "No Aadhaar on this device."); return
        }
        val (dt, cid, selected) = parseRequest(requestJson)
        docType = dt; credId = cid
        phaseState.value = Phase.Consent(ZkPresentationManager.checkSizes(mdoc, selected))
    }

    @Volatile private var submitting = false
    private fun approve(checks: List<SizeCheck>) {
        if (submitting) return // guard against a double tap / duplicate request
        submitting = true
        phaseState.value = Phase.Presenting(0)
        lifecycleScope.launch {
            try {
                val mdoc = loadMdoc() ?: throw IllegalStateException("Aadhaar not available")
                val provable = checks.filter { it.provable }.map { it.ref }
                if (provable.isEmpty()) throw IllegalStateException("Nothing shareable")
                val deviceKey = loadDeviceKey()
                val zk = ZkPresentationManager.generateZkDocument(mdoc, docType, provable, transcript, deviceKey)
                // Over BLE we send the raw DeviceResponse bytes (no base64/JSON) to save ~33% size.
                val deviceResponse = ZkPresentationManager.buildZkDeviceResponse(zk.zkDocument)
                client?.submit(deviceResponse)
            } catch (e: Exception) {
                Log.e(TAG, "proof/submit failed", e)
                phaseState.value = Phase.Done(false, "Failed: ${e.message}")
            }
        }
    }

    private fun parseRequest(requestJson: String): Triple<String, String, List<ZkPresentationManager.AttributeRef>> {
        val obj = JSONObject(requestJson)
        val cred = obj.getJSONObject("dcql_query").getJSONArray("credentials").getJSONObject(0)
        val cid = cred.optString("id", "aadhaar_zk")
        val meta = cred.optJSONObject("meta")
        val dt = meta?.optString("doctype_value") ?: ""
        val claimsArr = cred.optJSONArray("claims") ?: org.json.JSONArray()
        val refs = buildList {
            for (i in 0 until claimsArr.length()) {
                val path = claimsArr.getJSONObject(i).optJSONArray("path") ?: continue
                if (path.length() >= 2) add(ZkPresentationManager.AttributeRef(path.getString(0), path.getString(1)))
            }
        }
        return Triple(dt, cid, refs)
    }

    private fun loadMdoc(): ByteArray? {
        val f = File(filesDir, MainActivity.MDOC_FILE)
        if (!f.exists()) return null
        return runCatching { Base64.decode(f.readText().trim(), Base64.DEFAULT) }.getOrNull()
    }

    private fun loadDeviceKey(): java.security.PrivateKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val e = ks.getEntry(CredentialDownloadService.DEVICE_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Device key not found. Please re-download your Aadhaar credential.")
        return e.privateKey
    }

    private val nfcAdapter by lazy { android.nfc.NfcAdapter.getDefaultAdapter(this) }

    /**
     * While the share screen is up (reached via an NFC tap), the phones are often still touching.
     * Claim NFC reader mode with a no-op callback so stray taps are absorbed here instead of falling
     * through to the system's "unknown tag" dialog popping over the share screen.
     */
    override fun onResume() {
        super.onResume()
        runCatching {
            nfcAdapter?.enableReaderMode(
                this, { /* absorb */ },
                android.nfc.NfcAdapter.FLAG_READER_NFC_A or android.nfc.NfcAdapter.FLAG_READER_NFC_B or
                    android.nfc.NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
                    android.nfc.NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                null
            )
        }
    }

    override fun onPause() {
        super.onPause()
        runCatching { nfcAdapter?.disableReaderMode(this) }
    }

    override fun onDestroy() { super.onDestroy(); client?.stop() }

    private fun humanize(k: String) = k.split("_").joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
        .replace(Regex("(?<=[A-Za-z])(?=[0-9])"), " ")

    @Composable
    private fun BleScreen(phase: Phase) {
        AadhaarTheme {
            Surface(Modifier.fillMaxSize(), color = Aadhaar.Bg) {
                Column(Modifier.fillMaxSize()) {
                    BrandTopBar("Share Aadhaar")
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        when (phase) {
                            is Phase.Status -> {
                                Spacer(Modifier.height(24.dp))
                                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                    CircularProgressIndicator(Modifier.size(120.dp), color = Aadhaar.Navy, strokeWidth = 8.dp)
                                }
                                Text(phase.text, fontSize = 14.sp, color = Aadhaar.Muted,
                                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
                            }
                            is Phase.Presenting -> {
                                Spacer(Modifier.height(28.dp))
                                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                    Box(Modifier.size(150.dp), contentAlignment = Alignment.Center) {
                                        if (phase.progress <= 0) {
                                            CircularProgressIndicator(Modifier.fillMaxSize(), color = Aadhaar.Navy, strokeWidth = 10.dp)
                                        } else {
                                            CircularProgressIndicator(
                                                progress = { phase.progress / 100f },
                                                modifier = Modifier.fillMaxSize(),
                                                color = Aadhaar.Navy, trackColor = Aadhaar.Line, strokeWidth = 10.dp
                                            )
                                        }
                                        Text("${phase.progress}%", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Navy)
                                    }
                                }
                                Text("Sharing your proof securely…", fontSize = 13.sp, color = Aadhaar.Muted,
                                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
                            }
                            is Phase.Consent -> {
                                val provable = phase.checks.filter { it.provable }
                                Text("A verifier is requesting these details. Share only what's shown below?",
                                    fontSize = 14.sp, color = Aadhaar.Muted)
                                Card(
                                    shape = RoundedCornerShape(16.dp),
                                    colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
                                    elevation = CardDefaults.cardElevation(1.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                        phase.checks.forEach { c ->
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Box(
                                                    Modifier.size(28.dp).clip(CircleShape)
                                                        .background(if (c.provable) Aadhaar.GreenSoft else Aadhaar.Line),
                                                    contentAlignment = Alignment.Center
                                                ) { Text(if (c.provable) "✓" else "–", color = if (c.provable) Aadhaar.Green else Aadhaar.Muted, fontSize = 14.sp) }
                                                Spacer(Modifier.width(12.dp))
                                                Column {
                                                    Text(humanize(c.ref.element), fontSize = 15.sp, fontWeight = FontWeight.SemiBold,
                                                        color = if (c.provable) Aadhaar.Ink else Aadhaar.Muted)
                                                    if (!c.provable) Text("Too large to prove — won't be shared", fontSize = 11.sp, color = Aadhaar.Muted)
                                                }
                                            }
                                        }
                                    }
                                }
                                SaffronButton(if (provable.isEmpty()) "Nothing to share" else "Share", enabled = provable.isNotEmpty()) { approve(phase.checks) }
                                OutlineActionButton("Cancel") { finish() }
                            }
                            is Phase.Done -> {
                                Spacer(Modifier.height(32.dp))
                                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
                                    verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                    if (phase.success) {
                                        LottieSuccess(size = 150)
                                        Text("Shared", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Success)
                                    } else {
                                        Text("Not shared", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Red)
                                    }
                                    if (phase.message.isNotBlank())
                                        Text(phase.message, fontSize = 14.sp, color = Aadhaar.Muted, textAlign = TextAlign.Center)
                                }
                                Spacer(Modifier.height(24.dp))
                                PrimaryButton("Done") { finish() }
                            }
                        }
                    }
                }
            }
        }
    }
}
