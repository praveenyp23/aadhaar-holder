@file:OptIn(kotlin.time.ExperimentalTime::class)

package com.example.mdoc.common

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import co.nstant.`in`.cbor.model.Array as CborArray

/**
 * ISO/IEC 18013-5:2021 BLE GATT server (holder / mdoc side).
 *
 * Implements the peripheral-server mode transport:
 *  - Advertises the service UUID from the Device Engagement.
 *  - Uses Server2Client notifications to send data to the reader.
 *  - Receives data from the reader via Client2Server writes.
 *  - Messages are chunk-framed: first byte 0x01 = more, 0x00 = last chunk.
 *  - Full ISO 18013-5 session encryption (ECDH → HKDF → AES-GCM).
 */
class Iso18013BleServer(private val context: Context) {

    companion object {
        private const val TAG = "Iso18013BleServer"

        // ISO 18013-5 BLE characteristic UUIDs (per multipaz / identity-credential)
        val SERVICE_UUID: UUID       = UUID.fromString("0000ADB5-0000-1000-8000-00805F9B34FB")
        val STATE_UUID: UUID         = UUID.fromString("00000001-a123-48ce-896b-4c76973373e6")
        val CLIENT2SERVER_UUID: UUID = UUID.fromString("00000002-a123-48ce-896b-4c76973373e6")
        val SERVER2CLIENT_UUID: UUID = UUID.fromString("00000003-a123-48ce-896b-4c76973373e6")
        val CCCD_UUID: UUID          = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")

        const val STATE_READY       = 0x01.toByte()
        const val STATE_TERMINATION = 0x02.toByte()

        const val CHUNK_MORE = 0x01.toByte()   // 0x01 = more data coming
        const val CHUNK_LAST = 0x00.toByte()   // 0x00 = last (final) chunk
    }

    // ── Session state ─────────────────────────────────────────────────

    private var eDeviceKeyPair: KeyPair? = null
    private var encodedDeviceEngagement: ByteArray? = null
    private var handover: DataItem? = null      // null for QR, CBOR array for NFC
    private var mdocBytes: ByteArray? = null
    private var docType: String = ""
    private var negotiatedMtu: Int = 23         // default; updated on MTU change

    // ZK presentation mode (optional, off by default). When enabled, the holder responds with a
    // longfellow zero-knowledge proof of the selected attributes (carried in `zkDocuments`) instead
    // of a normal full-disclosure document. The standard QR/NFC flow is unaffected.
    private var zkMode: Boolean = false
    private var zkSelectedAttributes: List<ZkPresentationManager.AttributeRef> = emptyList()

    var onStatusUpdate: ((String) -> Unit)? = null
    var onPresentationComplete: ((success: Boolean, message: String) -> Unit)? = null

    // ── Android Bluetooth objects ─────────────────────────────────────

    private val btManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val btAdapter: BluetoothAdapter? = btManager?.adapter
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var connectedDevice: BluetoothDevice? = null
    private var server2ClientChar: BluetoothGattCharacteristic? = null
    private var stateChar: BluetoothGattCharacteristic? = null

    // ── Incoming message accumulator ──────────────────────────────────

    private val incomingBuffer = ByteArrayOutputStream()
    private val readerMsgCounter = AtomicInteger(1)
    private val deviceMsgCounter = AtomicInteger(1)
    private var sessionEstablished = false

    // ── Public API ────────────────────────────────────────────────────

    /**
     * Prepare a new presentation session.
     * Call [startAdvertising] afterwards to begin.
     */
    fun prepare(
        eDeviceKeyPair: KeyPair,
        encodedDeviceEngagement: ByteArray,
        mdocBytes: ByteArray,
        docType: String,
        handover: DataItem? = null
    ) {
        this.eDeviceKeyPair = eDeviceKeyPair
        this.encodedDeviceEngagement = encodedDeviceEngagement
        this.mdocBytes = mdocBytes
        this.docType = docType
        this.handover = handover
        // A plain prepare() defaults to the standard (non-ZK) flow. Call enableZkMode() afterwards
        // to switch this session to ZK presentation.
        this.zkMode = false
        this.zkSelectedAttributes = emptyList()
        incomingBuffer.reset()
        readerMsgCounter.set(1)
        deviceMsgCounter.set(1)
        sessionEstablished = false
    }

    /**
     * Switches the prepared session to ZK presentation, disclosing only [selected] attributes via a
     * longfellow proof. Call after [prepare] and before [startAdvertising].
     */
    fun enableZkMode(selected: List<ZkPresentationManager.AttributeRef>) {
        this.zkMode = true
        this.zkSelectedAttributes = selected
    }

    /** Open the GATT server, add the service, and start BLE advertising. */
    fun startAdvertising() {
        if (btManager == null || btAdapter == null) {
            onStatusUpdate?.invoke("Bluetooth not available")
            return
        }
        try {
            setupGattServer()
            advertise()
            onStatusUpdate?.invoke("Advertising – waiting for reader…")
        } catch (e: SecurityException) {
            Log.e(TAG, "Bluetooth permission denied", e)
            onStatusUpdate?.invoke("Bluetooth permission denied")
        } catch (e: Exception) {
            Log.e(TAG, "startAdvertising failed", e)
            onStatusUpdate?.invoke("BLE start failed")
        }
    }

    fun stop() {
        try { advertiser?.stopAdvertising(advCallback) } catch (_: Exception) {}
        try { gattServer?.close() } catch (_: Exception) {}
        gattServer = null
        connectedDevice = null
        server2ClientChar = null
        stateChar = null
    }

    // ── GATT server setup ─────────────────────────────────────────────

    private fun setupGattServer() {
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        // State characteristic  (notify + read + write-no-response)
        stateChar = BluetoothGattCharacteristic(
            STATE_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        ).also { it.addDescriptor(cccdDescriptor()) }

        // Client2Server  (write)
        val c2s = BluetoothGattCharacteristic(
            CLIENT2SERVER_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        // Server2Client  (notify)
        server2ClientChar = BluetoothGattCharacteristic(
            SERVER2CLIENT_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        ).also { it.addDescriptor(cccdDescriptor()) }

        service.addCharacteristic(stateChar!!)
        service.addCharacteristic(c2s)
        service.addCharacteristic(server2ClientChar!!)

        gattServer = btManager!!.openGattServer(context, gattCallback)
        gattServer!!.addService(service)
    }

    private fun cccdDescriptor() = BluetoothGattDescriptor(
        CCCD_UUID,
        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
    )

    private fun advertise() {
        advertiser = btAdapter!!.bluetoothLeAdvertiser
            ?: throw IllegalStateException("BLE advertiser unavailable")

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        advertiser!!.startAdvertising(settings, data, advCallback)
    }

    private val advCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(s: AdvertiseSettings?) { Log.d(TAG, "Advertising started") }
        override fun onStartFailure(err: Int) {
            Log.e(TAG, "Advertising failed: $err")
            onStatusUpdate?.invoke("BLE advertising failed ($err)")
        }
    }

    // ── GATT server callbacks ─────────────────────────────────────────

    private val gattCallback = object : BluetoothGattServerCallback() {

        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED && device != null) {
                connectedDevice = device
                Log.d(TAG, "Reader connected: ${device.address}")
                onStatusUpdate?.invoke("Reader connected")
                // Stop advertising once a reader is connected
                try { advertiser?.stopAdvertising(advCallback) } catch (_: Exception) {}
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "Reader disconnected")
                connectedDevice = null
            }
        }

        override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
            negotiatedMtu = mtu
            Log.d(TAG, "MTU changed: $mtu")
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?
        ) {
            // Reader enabling notifications on Server2Client or State
            if (descriptor.uuid == CCCD_UUID) {
                Log.d(TAG, "CCCD write for ${descriptor.characteristic.uuid}")
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, value)
                }
                // Reader enabling notifications on State or Server2Client
                if (descriptor.characteristic.uuid == STATE_UUID) {
                    Log.d(TAG, "Reader subscribed to State notifications")
                }
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor
        ) {
            if (descriptor.uuid == CCCD_UUID) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0,
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            when (characteristic.uuid) {
                STATE_UUID ->
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf(STATE_READY))
                else ->
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, ByteArray(0))
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?
        ) {
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }

            // Handle writes to State characteristic from reader
            if (characteristic.uuid == STATE_UUID && value != null && value.isNotEmpty()) {
                Log.d(TAG, "State characteristic written: 0x${value[0].toString(16)}")
                if (value[0] == STATE_READY) {
                    Log.d(TAG, "Reader signaled START — ready for data exchange")
                    onStatusUpdate?.invoke("Reader connected, exchanging data…")
                } else if (value[0] == STATE_TERMINATION) {
                    Log.d(TAG, "Reader signaled TERMINATION")
                    onStatusUpdate?.invoke("Session terminated by reader")
                }
                return
            }

            if (characteristic.uuid != CLIENT2SERVER_UUID || value == null || value.isEmpty()) return

            val flag = value[0]
            val payload = value.copyOfRange(1, value.size)
            incomingBuffer.write(payload)

            if (flag == CHUNK_LAST) {
                val fullMessage = incomingBuffer.toByteArray()
                incomingBuffer.reset()
                Log.d(TAG, "Full message received: ${fullMessage.size} bytes")
                onStatusUpdate?.invoke("Processing request…")
                handleIncomingMessage(fullMessage)
            }
        }
    }

    // ── Message handling ──────────────────────────────────────────────

    private fun handleIncomingMessage(sessionBytes: ByteArray) {
        // After session is established, subsequent messages are SessionData (status/termination)
        if (sessionEstablished) {
            try {
                val sd = Iso18013Crypto.parseSessionData(sessionBytes)
                Log.d(TAG, "SessionData received: status=${sd.status}, hasData=${sd.encryptedData != null}")
                if (sd.status != null) {
                    Log.d(TAG, "Session terminated by reader with status ${sd.status}")
                    onStatusUpdate?.invoke("Session complete (status ${sd.status})")
                }
            } catch (e: Exception) {
                Log.d(TAG, "Ignoring post-session message: ${e.message}")
            }
            return
        }

        Thread {
            try {
                val kp = eDeviceKeyPair ?: throw IllegalStateException("No eDeviceKey")
                val encDE = encodedDeviceEngagement ?: throw IllegalStateException("No DeviceEngagement")
                val mdoc = mdocBytes ?: throw IllegalStateException("No mdoc")

                // Parse Session Establishment (first message contains eReaderKey)
                val se = Iso18013Crypto.parseSessionEstablishment(sessionBytes)
                Log.d(TAG, "═══════════════════════════════════════════════════════")
                Log.d(TAG, "SESSION ESTABLISHMENT")
                Log.d(TAG, "═══════════════════════════════════════════════════════")
                Log.d(TAG, "Parsed eReaderKey from reader")

                // Build session transcript
                val encodedEReaderKey = se.eReaderKeyEncoded
                val encodedSessionTranscript = Iso18013Crypto.buildSessionTranscript(
                    encDE, encodedEReaderKey, handover
                )
                Log.d(TAG, "DeviceEngagement (${encDE.size} bytes): ${encDE.joinToString("") { "%02x".format(it) }}")
                Log.d(TAG, "EReaderKey (${encodedEReaderKey.size} bytes): ${encodedEReaderKey.joinToString("") { "%02x".format(it) }}")
                Log.d(TAG, "Handover: ${handover?.toString() ?: "null"}")
                Log.d(TAG, "SessionTranscript encoded (${encodedSessionTranscript.size} bytes):")
                Log.d(TAG, "  ${encodedSessionTranscript.joinToString("") { "%02x".format(it) }}")

                // ECDH + key derivation
                val sharedSecret = Iso18013Crypto.performEcdh(kp.private, se.eReaderKeyPublic)
                Log.d(TAG, "SharedSecret (${sharedSecret.size} bytes): ${sharedSecret.joinToString("") { "%02x".format(it) }}")
                val keys = Iso18013Crypto.deriveSessionKeys(sharedSecret, encodedSessionTranscript)
                Log.d(TAG, "Keys derived:")
                Log.d(TAG, "  SKDevice (${keys.skDevice.size} bytes): ${keys.skDevice.joinToString("") { "%02x".format(it) }}")
                Log.d(TAG, "  SKReader (${keys.skReader.size} bytes): ${keys.skReader.joinToString("") { "%02x".format(it) }}")
                Log.d(TAG, "  EMacKey  (${keys.eMacKey.size} bytes): ${keys.eMacKey.joinToString("") { "%02x".format(it) }}")

                // Decrypt DeviceRequest (reader→device direction)
                val iv = Iso18013Crypto.buildIv(readerMsgCounter.getAndIncrement(), deviceToReader = false)
                val encodedDeviceRequest = Iso18013Crypto.aesGcmDecrypt(keys.skReader, iv, se.encryptedData)
                Log.d(TAG, "───────────────────────────────────────────────────────")
                Log.d(TAG, "DeviceRequest decrypted: ${encodedDeviceRequest.size} bytes")
                Log.d(TAG, "RAW DeviceRequest CBOR: ${encodedDeviceRequest.joinToString("") { "%02x".format(it) }}")
                Log.d(TAG, "───────────────────────────────────────────────────────")

                // Parse DeviceRequest to see what the reader is asking for
                val requestedDocs = Iso18013Crypto.parseDeviceRequest(encodedDeviceRequest)
                Log.d(TAG, "Reader requested ${requestedDocs.size} docType(s):")
                for (req in requestedDocs) {
                    Log.d(TAG, "  - docType='${req.docType}' namespaces=${req.requestedNamespaces.keys}")
                    for ((ns, elems) in req.requestedNamespaces) {
                        Log.d(TAG, "    namespace='$ns' elements=$elems")
                    }
                }
                Log.d(TAG, "Holder credential docType='$docType'")

                // Check if any requested docType matches our credential
                val matchingRequest = requestedDocs.find { it.docType == docType }
                if (matchingRequest != null) {
                    Log.d(TAG, "DocType MATCH found: '${matchingRequest.docType}'")
                } else {
                    Log.w(TAG, "NO DocType match! Reader wants ${requestedDocs.map { it.docType }} but holder has '$docType'")
                }

                // Build DeviceResponse — either a ZK proof (zkDocuments) or a normal disclosure.
                val encodedDeviceResponse = if (zkMode) {
                    Log.d(TAG, "ZK mode: generating longfellow proof for ${zkSelectedAttributes.size} attribute(s)")
                    onStatusUpdate?.invoke("Generating ZK proof…")
                    val zkResult = kotlinx.coroutines.runBlocking {
                        ZkPresentationManager.generateZkDocument(
                            mdocBytes = mdoc,
                            docType = docType,
                            selected = zkSelectedAttributes,
                            encodedSessionTranscript = encodedSessionTranscript,
                            devicePrivateKey = kp.private
                        )
                    }
                    Log.d(TAG, "ZK proof ready (circuit='${zkResult.systemSpec.id}', ${zkResult.zkDocument.proof.size} proof bytes)")
                    ZkPresentationManager.buildZkDeviceResponse(zkResult.zkDocument)
                } else {
                    val requestedNamespaces = matchingRequest?.requestedNamespaces ?: emptyMap()
                    Iso18013Crypto.buildDeviceResponse(
                        mdoc, docType, encodedSessionTranscript, keys.eMacKey, requestedNamespaces
                    )
                }
                Log.d(TAG, "DeviceResponse built: ${encodedDeviceResponse.size} bytes")

                // Encrypt DeviceResponse (device→reader direction)
                val respIv = Iso18013Crypto.buildIv(deviceMsgCounter.getAndIncrement(), deviceToReader = true)
                val encryptedResponse = Iso18013Crypto.aesGcmEncrypt(keys.skDevice, respIv, encodedDeviceResponse)

                // Wrap in SessionData CBOR
                val sessionData = Iso18013Crypto.encodeSessionData(encryptedResponse)

                // Send via Server2Client notifications
                sendChunkedMessage(sessionData)

                sessionEstablished = true
                onStatusUpdate?.invoke("Response sent!")
                onPresentationComplete?.invoke(true, "Presentation successful")

            } catch (e: Exception) {
                Log.e(TAG, "Presentation failed", e)
                onStatusUpdate?.invoke("Presentation failed: ${e.message}")
                onPresentationComplete?.invoke(false, e.message ?: "Unknown error")
            }
        }.start()
    }

    // ── Chunked notification send ─────────────────────────────────────

    private fun sendChunkedMessage(message: ByteArray) {
        val device = connectedDevice ?: return
        val char = server2ClientChar ?: return
        // Max attribute value = min(MTU-3, 512). Subtract 1 for the flag byte.
        val maxAttrValue = minOf(negotiatedMtu - 3, 512)
        val chunkDataSize = maxOf(maxAttrValue - 1, 20)
        Log.d(TAG, "sendChunkedMessage: ${message.size} bytes, mtu=$negotiatedMtu, chunkDataSize=$chunkDataSize")
        var offset = 0

        while (offset < message.size) {
            val end = minOf(offset + chunkDataSize, message.size)
            val isLast = (end == message.size)
            val chunk = ByteArray(1 + (end - offset))
            chunk[0] = if (isLast) CHUNK_LAST else CHUNK_MORE
            System.arraycopy(message, offset, chunk, 1, end - offset)

            char.value = chunk
            try {
                gattServer?.notifyCharacteristicChanged(device, char, false)
            } catch (e: SecurityException) {
                Log.e(TAG, "Notification permission denied", e)
                return
            }
            offset = end
            // Small delay between notifications to avoid overwhelming the stack
            Thread.sleep(20)
        }
        Log.d(TAG, "Sent ${message.size} bytes in chunks (mtu=$negotiatedMtu)")
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private fun notifyState(device: BluetoothDevice, state: Byte) {
        val char = stateChar ?: return
        char.value = byteArrayOf(state)
        try {
            gattServer?.notifyCharacteristicChanged(device, char, false)
        } catch (e: SecurityException) {
            Log.w(TAG, "State notify permission denied", e)
        }
    }
}
