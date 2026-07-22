@file:OptIn(kotlin.time.ExperimentalTime::class)

package com.example.mdoc.holder

import android.util.Log
import com.example.mdoc.common.CredentialDownloadService
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.digitalcredentials.DigitalCredentials
import org.multipaz.digitalcredentials.getDefault
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.Aadhaar
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.mdoc.zkp.longfellow.LongfellowZkSystem
import org.multipaz.presentment.PresentmentSource
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.util.Platform

/**
 * Registers the downloaded Aadhaar mdoc with Android's Credential Manager so the app can answer
 * **W3C Digital Credentials API** requests (ISO 18013-7 Annex C and OpenID4VP-over-DC-API), both
 * same-device and cross-device (the FIDO/hybrid QR routed by Google Play Services).
 *
 * The credential is imported into a Multipaz [DocumentStore] and **bound to the real
 * `mdoc_device_key`** (the DeviceKey UIDAI embedded in the MSO) via
 * [AndroidKeystoreSecureArea.createKeyForExistingAlias] — so the device-signed response Multipaz
 * produces is signed by the genuine DeviceKey and the longfellow circuit's holder-binding check
 * passes. The download flow and that key are untouched.
 *
 * Actual request handling + ZK proof + consent is done by Multipaz's presentment via
 * [DcApiPresentmentActivity], using the [PresentmentSource] exposed here (which carries the
 * longfellow [ZkSystemRepository]).
 */
object DcApiManager {

    private const val TAG = "MDOC_DCAPI"
    const val DOMAIN = "mdoc"

    private val lock = Mutex()
    private var documentStore: DocumentStore? = null
    private var secureArea: AndroidKeystoreSecureArea? = null
    private var documentTypeRepository: DocumentTypeRepository? = null
    private var presentmentSourceInternal: PresentmentSource? = null

    @Volatile
    var registered: Boolean = false
        private set

    /** Initializes Multipaz's application context. Safe to call multiple times. */
    fun initContext(applicationContext: android.content.Context) {
        runCatching { org.multipaz.context.initializeApplication(applicationContext) }
            .onFailure { Log.d(TAG, "initializeApplication: ${it.message}") }
    }

    private suspend fun ensureStore() {
        if (documentStore != null) return
        val storage = Platform.nonBackedUpStorage
        val sa = AndroidKeystoreSecureArea.create(storage)
        val repo = SecureAreaRepository.Builder().add(sa).build()
        val store = buildDocumentStore(storage, repo) {}
        val docTypes = DocumentTypeRepository().apply { addDocumentType(Aadhaar.getDocumentType()) }
        val zkRepo = ZkSystemRepository().apply {
            add(LongfellowZkSystem().apply { addDefaultCircuits() })
        }
        secureArea = sa
        documentStore = store
        documentTypeRepository = docTypes
        presentmentSourceInternal = SimplePresentmentSource(
            documentStore = store,
            documentTypeRepository = docTypes,
            zkSystemRepository = zkRepo,
            // Use ECDSA device authentication (longfellow verifies a deviceSignature).
            domainsMdocSignature = listOf(DOMAIN)
        )
        Log.d(TAG, "DocumentStore + PresentmentSource initialized")
    }

    /**
     * Imports [mdocBytes] (a `{ issuerSigned: { issuerAuth, nameSpaces } }` CBOR map) bound to the
     * real device key, and registers it with the OS Credential Manager for DC API presentment.
     */
    suspend fun importAndRegister(mdocBytes: ByteArray) = lock.withLock {
        ensureStore()
        val store = documentStore!!
        val sa = secureArea!!

        // Re-import cleanly each time so we don't accumulate duplicates.
        store.listDocuments().forEach { store.deleteDocument(it.identifier) }

        val issuerSignedBytes = Cbor.encode(Cbor.decode(mdocBytes)["issuerSigned"])
        val alias = CredentialDownloadService.DEVICE_KEY_ALIAS

        // Adopt the existing KeyStore device key (the MSO's DeviceKey) into the SecureArea so the
        // device-signed response is produced by the genuine key — preserving holder binding.
        sa.createKeyForExistingAlias(alias)

        val document = store.createDocument(displayName = "Aadhaar", typeDisplayName = "Aadhaar")
        val credential = MdocCredential.createForExistingAlias(
            document = document,
            asReplacementForIdentifier = null,
            domain = DOMAIN,
            secureArea = sa,
            docType = Aadhaar.AADHAAR_DOCTYPE,
            existingKeyAlias = alias
        )
        credential.certify(ByteString(issuerSignedBytes))
        Log.d(TAG, "Imported Aadhaar credential bound to device key '$alias'")

        val dc = DigitalCredentials.getDefault()
        dc.register(store, documentTypeRepository!!, dc.supportedProtocols)
        registered = true
        Log.d(TAG, "Registered with Credential Manager. Protocols: ${dc.supportedProtocols}")
    }

    /** The presentment source used by [DcApiPresentmentActivity] to answer requests. */
    suspend fun presentmentSource(): PresentmentSource {
        ensureStore()
        return presentmentSourceInternal!!
    }
}
