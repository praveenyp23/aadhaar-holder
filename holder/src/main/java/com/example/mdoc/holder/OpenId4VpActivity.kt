package com.example.mdoc.holder

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
import com.example.mdoc.common.OpenId4VpZkClient
import com.example.mdoc.common.ZkPresentationManager
import com.example.mdoc.common.ZkPresentationManager.SizeCheck
import kotlinx.coroutines.launch
import java.io.File
import java.security.KeyStore

/**
 * Handles an OpenID4VP request (same-device deep link or scanned cross-device URI): fetches the
 * request, shows a consent prompt, and — only on approval — generates a holder-bound longfellow ZK
 * proof and returns the vp_token to the verifier via OpenId4VpZkClient.
 *
 * Attributes whose value exceeds 64 bytes, or whose IssuerSignedItem exceeds 119 bytes, cannot be
 * proven by the longfellow circuit, so they are shown but disabled here and excluded from the proof.
 */
class OpenId4VpActivity : ComponentActivity() {

    companion object {
        const val TAG = "MDOC_ZK_OID4VP_ACT"
        const val EXTRA_URI = "openid4vp_uri"
    }

    private val brand = Color(0xFF003772)

    private sealed interface Phase {
        object Loading : Phase
        data class Consent(val req: OpenId4VpZkClient.RequestInfo, val checks: List<SizeCheck>) : Phase
        data class Presenting(val req: OpenId4VpZkClient.RequestInfo) : Phase
        data class Done(val success: Boolean, val message: String) : Phase
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data?.toString() ?: intent.getStringExtra(EXTRA_URI)
        if (uri == null) { finish(); return }

        setContent {
            var phase by remember { mutableStateOf<Phase>(Phase.Loading) }

            LaunchedEffect(uri) {
                phase = try {
                    val mdoc = loadMdoc()
                        ?: return@LaunchedEffect run {
                            phase = Phase.Done(false, "No Aadhaar on this device. Download it first.")
                        }
                    // Pin the verifier: verify the request's signature against this bundled certificate.
                    val trustedCert = runCatching {
                        resources.openRawResource(com.mdocholder.app.R.raw.verifier_cert).use {
                            java.security.cert.CertificateFactory.getInstance("X.509")
                                .generateCertificate(it) as java.security.cert.X509Certificate
                        }
                    }.getOrNull()
                    val req = OpenId4VpZkClient.fetchRequest(uri, trustedCert)
                    val selected = req.requestedClaims.map { ZkPresentationManager.AttributeRef(it.namespace, it.element) }
                    Phase.Consent(req, ZkPresentationManager.checkSizes(mdoc, selected))
                } catch (e: Exception) {
                    Log.e(TAG, "fetchRequest failed", e)
                    Phase.Done(false, "Couldn't read the verifier's request: ${e.message}")
                }
            }

            OpenId4VpScreen(
                phase = phase,
                onApprove = { consent ->
                    phase = Phase.Presenting(consent.req)
                    lifecycleScope.launch { phase = present(consent) }
                },
                onDeny = { finish() },
                onClose = { finish() }
            )
        }
    }

    private suspend fun present(consent: Phase.Consent): Phase {
        return try {
            val mdoc = loadMdoc() ?: return Phase.Done(false, "Aadhaar not available.")
            val provable = consent.checks.filter { it.provable }.map { it.ref }
            if (provable.isEmpty()) {
                return Phase.Done(false, "None of the requested attributes can be shared as a proof (all exceed the size limit).")
            }
            val deviceKey = loadDevicePrivateKey()
            val result = OpenId4VpZkClient.presentZk(consent.req, mdoc, consent.req.docType ?: "", provable, deviceKey)
            if (result.httpCode in 200..299) {
                Phase.Done(true, "Your Aadhaar details were shared securely.")
            } else {
                Phase.Done(false, "Verifier returned HTTP ${result.httpCode}: ${result.body.take(200)}")
            }
        } catch (e: ZkPresentationManager.NoMatchingCircuitException) {
            Phase.Done(false, e.message ?: "No matching circuit.")
        } catch (e: Exception) {
            Log.e(TAG, "presentZk failed", e)
            Phase.Done(false, "Failed to present: ${e.message}")
        }
    }

    private fun loadMdoc(): ByteArray? {
        val f = File(filesDir, MainActivity.MDOC_FILE)
        if (!f.exists()) return null
        return runCatching { Base64.decode(f.readText().trim(), Base64.DEFAULT) }.getOrNull()
    }

    private fun loadDevicePrivateKey(): java.security.PrivateKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(CredentialDownloadService.DEVICE_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Device key not found. Re-download your Aadhaar.")
        return entry.privateKey
    }

    private fun humanize(k: String) = k.split("_").joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
        .replace(Regex("(?<=[A-Za-z])(?=[0-9])"), " ")

    @Composable
    private fun OpenId4VpScreen(
        phase: Phase,
        onApprove: (Phase.Consent) -> Unit,
        onDeny: () -> Unit,
        onClose: () -> Unit
    ) {
        AadhaarTheme {
            Surface(modifier = Modifier.fillMaxSize(), color = Aadhaar.Bg) {
                Column(Modifier.fillMaxSize()) {
                    BrandTopBar("Share Aadhaar")
                    Column(
                        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        when (phase) {
                            is Phase.Loading -> {
                                Spacer(Modifier.height(24.dp))
                                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                    CircularProgressIndicator(Modifier.size(110.dp), color = Aadhaar.Navy, strokeWidth = 8.dp)
                                }
                                Text("Loading request…", fontSize = 14.sp, color = Aadhaar.Muted,
                                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
                            }
                            is Phase.Consent -> ConsentBody(phase, onApprove, onDeny)
                            is Phase.Presenting -> {
                                Spacer(Modifier.height(24.dp))
                                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                    CircularProgressIndicator(Modifier.size(110.dp), color = Aadhaar.Navy, strokeWidth = 8.dp)
                                }
                                Text("Sharing your proof securely…", fontSize = 13.sp, color = Aadhaar.Muted,
                                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center)
                            }
                            is Phase.Done -> DoneBody(phase, onClose)
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun ConsentBody(
        consent: Phase.Consent,
        onApprove: (Phase.Consent) -> Unit,
        onDeny: () -> Unit
    ) {
        val provable = consent.checks.filter { it.provable }
        Text("A verifier is requesting these details. Share only what's shown below?",
            fontSize = 14.sp, color = Aadhaar.Muted)
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
            elevation = CardDefaults.cardElevation(1.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                consent.checks.forEach { c ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier.size(28.dp).clip(CircleShape).background(if (c.provable) Aadhaar.GreenSoft else Aadhaar.Line),
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
        Spacer(Modifier.height(4.dp))
        SaffronButton(if (provable.isEmpty()) "Nothing to share" else "Share", enabled = provable.isNotEmpty()) { onApprove(consent) }
        OutlineActionButton("Cancel") { onDeny() }
    }

    @Composable
    private fun DoneBody(done: Phase.Done, onClose: () -> Unit) {
        Spacer(Modifier.height(40.dp))
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (done.success) {
                LottieSuccess(size = 150)
                Text("Shared", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Success)
            } else {
                Text("Not shared", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Red)
            }
            Text(done.message, fontSize = 14.sp, color = Aadhaar.Muted, textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 8.dp))
        }
        Spacer(Modifier.height(24.dp))
        PrimaryButton("Done") { onClose() }
    }
}
