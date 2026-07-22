package com.example.mdoc.common

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

object BleConstants {
    // ISO 18013-5 standard UUIDs
    val SERVICE_UUID: UUID = UUID.fromString("0000ADB5-0000-1000-8000-00805F9B34FB")
    val STATE_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000ADB6-0000-1000-8000-00805F9B34FB")
    val CLIENT2SERVER_UUID: UUID = UUID.fromString("0000ADB7-0000-1000-8000-00805F9B34FB")
    val SERVER2CLIENT_UUID: UUID = UUID.fromString("0000ADB8-0000-1000-8000-00805F9B34FB")
    val CHARACTERISTIC_UUID: UUID = SERVER2CLIENT_UUID  // Backward compatibility
    
    const val MTU_SIZE = 512
}

class BleTransferManager(private val context: Context) {
    
    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager?.adapter
    
    private var gattServer: BluetoothGattServer? = null
    private var gattClient: BluetoothGatt? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    
    /** Client: accumulated chunks for long read; null when not in a multi-read. */
    private val clientChunks = mutableListOf<ByteArray>()
    private var clientServer2ClientChar: BluetoothGattCharacteristic? = null
    
    var onDataReceived: ((String) -> Unit)? = null
    var onConnectionStateChanged: ((Boolean) -> Unit)? = null
    /** Optional status messages for in-app display (e.g. "Scanning...", "Connected", "Received 2048 bytes"). */
    var onStatus: ((String) -> Unit)? = null
    
    private var dataToSend: String? = null
    
    /** Per-device read offset for chunked SERVER2CLIENT; client does multiple reads, we advance each time. */
    private val serverReadOffsetByDevice = ConcurrentHashMap<BluetoothDevice, Int>()
    
    fun startServer(mdocBase64: String) {
        if (bluetoothManager == null || bluetoothAdapter == null) {
            Log.e("BLE_MANAGER", "Bluetooth not available on this device")
            return
        }
        dataToSend = mdocBase64
        try {
            val service = BluetoothGattService(
                BleConstants.SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY
            )
            
            // State characteristic
            val stateChar = BluetoothGattCharacteristic(
                BleConstants.STATE_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            
            // Client to Server characteristic
            val client2ServerChar = BluetoothGattCharacteristic(
                BleConstants.CLIENT2SERVER_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            
            // Server to Client characteristic (main data transfer)
            val server2ClientChar = BluetoothGattCharacteristic(
                BleConstants.SERVER2CLIENT_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            
            service.addCharacteristic(stateChar)
            service.addCharacteristic(client2ServerChar)
            service.addCharacteristic(server2ClientChar)
            
            gattServer = bluetoothManager.openGattServer(context, gattServerCallback)
            gattServer?.addService(service)
            
            startAdvertising()
        } catch (e: SecurityException) {
            Log.e("BLE_MANAGER", "Bluetooth permission not granted", e)
        } catch (e: Exception) {
            Log.e("BLE_MANAGER", "Error starting BLE server", e)
        }
    }
    
    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                onConnectionStateChanged?.invoke(true)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                device?.let { serverReadOffsetByDevice.remove(it) }
                onConnectionStateChanged?.invoke(false)
            }
        }
        
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice?,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic?
        ) {
            when (characteristic?.uuid) {
                BleConstants.SERVER2CLIENT_UUID, BleConstants.CHARACTERISTIC_UUID -> {
                    val data = dataToSend?.toByteArray() ?: ByteArray(0)
                    val effectiveOffset = device?.let { serverReadOffsetByDevice.getOrPut(it) { 0 } } ?: 0
                    val chunk = if (effectiveOffset < data.size) {
                        data.copyOfRange(effectiveOffset, minOf(effectiveOffset + BleConstants.MTU_SIZE, data.size))
                    } else {
                        ByteArray(0)
                    }
                    device?.let { serverReadOffsetByDevice[it] = effectiveOffset + chunk.size }
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, effectiveOffset, chunk)
                }
                BleConstants.STATE_CHARACTERISTIC_UUID -> {
                    // Return ready state
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf(0x01))
                }
                else -> {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                }
            }
        }
        
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            if (characteristic?.uuid == BleConstants.CLIENT2SERVER_UUID) {
                // Handle received data from client if needed
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            }
        }
    }
    
    private fun startAdvertising() {
        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.w("BLE_MANAGER", "BLE advertiser not available (Bluetooth may be off)")
            return
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()
        
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(BleConstants.SERVICE_UUID))
            .build()
        
        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
        } catch (e: SecurityException) {
            Log.e("BLE_MANAGER", "Bluetooth advertise permission not granted", e)
        } catch (e: Exception) {
            Log.e("BLE_MANAGER", "Error starting BLE advertising", e)
        }
    }
    
    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            // Advertising started successfully
        }
        
        override fun onStartFailure(errorCode: Int) {
            // Advertising failed
        }
    }
    
    fun startScanning() {
        try {
            scanner = bluetoothAdapter?.bluetoothLeScanner
            if (scanner == null) {
                onStatus?.invoke("Bluetooth scanner not available")
                return
            }
            onStatus?.invoke("Scanning for device...")
            scanner?.startScan(scanCallback)
        } catch (e: Exception) {
            Log.e("BLE_MANAGER", "Error starting BLE scan", e)
            onStatus?.invoke("Connection failed. Try again.")
        }
    }
    
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            result?.device?.let { device ->
                if (result.scanRecord?.serviceUuids?.contains(ParcelUuid(BleConstants.SERVICE_UUID)) == true) {
                    scanner?.stopScan(this)
                    onStatus?.invoke("Device found. Connecting...")
                    connectToDevice(device)
                }
            }
        }
    }
    
    private fun connectToDevice(device: BluetoothDevice) {
        try {
            gattClient = device.connectGatt(context, false, gattClientCallback)
        } catch (e: Exception) {
            Log.e("BLE_MANAGER", "Error connecting to device", e)
            onStatus?.invoke("Connection failed. Try again.")
            onConnectionStateChanged?.invoke(false)
        }
    }
    
    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt?, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                onStatus?.invoke("Connected. Receiving data...")
                onConnectionStateChanged?.invoke(true)
                gatt?.requestMtu(BleConstants.MTU_SIZE)
                gatt?.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                onStatus?.invoke("Disconnected")
                onConnectionStateChanged?.invoke(false)
            }
        }
        
        override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                onStatus?.invoke("Connection failed. Try again.")
                return
            }
            val service = gatt?.getService(BleConstants.SERVICE_UUID) ?: return
            val characteristic = service.getCharacteristic(BleConstants.SERVER2CLIENT_UUID)
                ?: service.getCharacteristic(BleConstants.CHARACTERISTIC_UUID) ?: return
            clientServer2ClientChar = characteristic
            clientChunks.clear()
            gatt.readCharacteristic(characteristic)
        }
        
        override fun onCharacteristicRead(
            gatt: BluetoothGatt?,
            characteristic: BluetoothGattCharacteristic?,
            status: Int
        ) {
            val uuid = characteristic?.uuid
            if (status != BluetoothGatt.GATT_SUCCESS ||
                (uuid != BleConstants.SERVER2CLIENT_UUID && uuid != BleConstants.CHARACTERISTIC_UUID)) return
            val data = characteristic?.value ?: return
            clientChunks.add(data)
            if (data.size >= BleConstants.MTU_SIZE) {
                gatt?.readCharacteristic(characteristic)
                return
            }
            val full = clientChunks.fold(byteArrayOf()) { acc, chunk -> acc + chunk }
            clientChunks.clear()
            clientServer2ClientChar = null
            val receivedData = String(full, Charsets.UTF_8)
            onStatus?.invoke("Received ${full.size} bytes")
            onDataReceived?.invoke(receivedData)
        }
    }
    
    fun stopServer() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (e: Exception) {
            Log.w("BLE_MANAGER", "Error stopping advertiser", e)
        }
        try {
            gattServer?.close()
        } catch (e: Exception) {
            Log.w("BLE_MANAGER", "Error closing GATT server", e)
        }
        gattServer = null
    }
    
    fun stopClient() {
        try {
            scanner?.stopScan(scanCallback)
        } catch (e: Exception) {
            Log.w("BLE_MANAGER", "Error stopping scanner", e)
        }
        try {
            gattClient?.close()
        } catch (e: Exception) {
            Log.w("BLE_MANAGER", "Error closing GATT client", e)
        }
        gattClient = null
        clientChunks.clear()
        clientServer2ClientChar = null
    }
    
    fun cleanup() {
        stopServer()
        stopClient()
    }
}
