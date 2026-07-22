package com.example.mdoc.holder

import android.util.Base64
import android.util.Log
import com.example.mdoc.common.MdocParser

/**
 * Extracts all fields from an mDoc (ISO 18013-5) credential
 * Uses proper CBOR decoding via MdocParser
 */
object MdocFieldExtractor {
    
    fun extractAllFields(mdocBase64: String): Pair<String, Map<String, String>> {
        return try {
            Log.d("MDOC_EXTRACTOR", "Starting extraction of ${mdocBase64.length} byte credential")
            
            val parsedMdoc = MdocParser.parseBase64Mdoc(mdocBase64)
            
            if (parsedMdoc == null) {
                Log.e("MDOC_EXTRACTOR", "Failed to parse mDoc - parseBase64Mdoc returned null")
                // Return fallback data from the credential itself
                return tryFallbackExtraction(mdocBase64)
            }
            
            // Convert attributes to String map, handling various types
            val fields = mutableMapOf<String, String>()
            Log.d("MDOC_EXTRACTOR", "Found ${parsedMdoc.attributes.size} attributes in parsed credential")
            
            for ((key, value) in parsedMdoc.attributes) {
                fields[key] = when (value) {
                    is String -> value
                    is Number -> value.toString()
                    is Boolean -> if (value) "Yes" else "No"
                    is List<*> -> value.joinToString(", ")
                    is Map<*, *> -> value.toString()
                    else -> value.toString()
                }
                Log.d("MDOC_EXTRACTOR", "  Field: $key = ${fields[key]?.take(50)}")
            }
            
            val docType = parsedMdoc.namespace.takeIf { it.isNotEmpty() } ?: "org.iso.18013.5.1"
            Log.d("MDOC_EXTRACTOR", "Successfully extracted ${fields.size} fields from namespace: $docType")
            
            Pair(docType, fields.toSortedMap())
        } catch (e: Exception) {
            Log.e("MDOC_EXTRACTOR", "Failed to extract fields - attempting fallback", e)
            tryFallbackExtraction(mdocBase64)
        }
    }
    
    private fun tryFallbackExtraction(mdocBase64: String): Pair<String, Map<String, String>> {
        return try {
            // Attempt to search for common field names in the base64 string
            val decodedBytes = Base64.decode(mdocBase64, Base64.DEFAULT)
            val decodedString = String(decodedBytes, Charsets.ISO_8859_1)
            
            val fields = mutableMapOf<String, String>()
            val fieldNames = listOf(
                "resident_name", "given_name", "family_name", "dob", "date_of_birth",
                "gender", "vtc", "district", "state", "building", "street", 
                "address", "pincode", "mobile", "email", "aadhar_type"
            )
            
            for (fieldName in fieldNames) {
                val index = decodedString.indexOf(fieldName)
                if (index >= 0) {
                    // Try to extract value after field name
                    val valueStart = index + fieldName.length + 1
                    val valueEnd = minOf(valueStart + 100, decodedString.length)
                    val valueSection = decodedString.substring(valueStart, valueEnd)
                    
                    // Extract printable ASCII characters
                    val printable = valueSection.filter { it.isLetterOrDigit() || it == ' ' || it == '-' || it == '.' }
                    if (printable.isNotEmpty()) {
                        fields[fieldName] = printable.trim().take(50)
                    }
                }
            }
            
            Log.d("MDOC_EXTRACTOR", "Fallback extraction found ${fields.size} fields")
            Pair("vin.gov.uidai.aadhaar.1", fields)
        } catch (e: Exception) {
            Log.e("MDOC_EXTRACTOR", "Fallback extraction also failed", e)
            Pair("Error", mapOf("Status" to "Unable to parse credential"))
        }
    }
}
