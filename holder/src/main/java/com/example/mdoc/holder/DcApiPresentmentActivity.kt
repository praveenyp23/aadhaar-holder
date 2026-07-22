package com.example.mdoc.holder

import org.multipaz.compose.digitalcredentials.CredentialManagerPresentmentActivity

/**
 * Receives W3C Digital Credentials API `GET_CREDENTIAL` requests from the OS Credential Manager
 * (same-device Chrome, or the cross-device FIDO hybrid routed by Google Play Services) and answers
 * them via Multipaz's presentment.
 *
 * The base class handles: extracting the request, computing the OpenID4VP-DC-API session transcript,
 * showing the **consent prompt**, generating the response (a longfellow **ZK proof** when the
 * verifier asks for `mso_mdoc_zk`, since [DcApiManager]'s source carries a longfellow
 * ZkSystemRepository), encrypting it, and returning it to the browser.
 */
class DcApiPresentmentActivity : CredentialManagerPresentmentActivity() {
    override suspend fun getSettings(): Settings {
        DcApiManager.initContext(applicationContext)
        val source = DcApiManager.presentmentSource()
        val privilegedAllowList = runCatching {
            assets.open("privilegedUserAgents.json").bufferedReader().use { it.readText() }
        }.getOrDefault("{\"apps\":[]}")
        return Settings(source = source, privilegedAllowList = privilegedAllowList)
    }
}
