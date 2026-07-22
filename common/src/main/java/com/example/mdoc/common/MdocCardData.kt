package com.example.mdoc.common

/**
 * Minimal card data for display (name, DOB, gender, address, photo).
 * Used by holder and reader for consistent card art.
 */
data class MdocCardData(
    val name: String,
    val dateOfBirth: String,
    val gender: String,
    val address: String,
    val residentImageBytes: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as MdocCardData
        if (name != other.name) return false
        if (dateOfBirth != other.dateOfBirth) return false
        if (gender != other.gender) return false
        if (address != other.address) return false
        if (residentImageBytes != null) {
            if (other.residentImageBytes == null) return false
            if (!residentImageBytes.contentEquals(other.residentImageBytes)) return false
        } else if (other.residentImageBytes != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = name.hashCode()
        result = 31 * result + dateOfBirth.hashCode()
        result = 31 * result + gender.hashCode()
        result = 31 * result + address.hashCode()
        result = 31 * result + (residentImageBytes?.contentHashCode() ?: 0)
        return result
    }
}

object MdocCardExtractor {
    private fun getStr(attrs: Map<String, Any>, vararg keys: String): String {
        for (key in keys) {
            val v = attrs[key] ?: continue
            val s = when (v) {
                is String -> v
                is Number -> v.toString()
                is Boolean -> if (v) "Yes" else "No"
                else -> v.toString()
            }
            if (s.isNotBlank()) return s.trim()
        }
        return ""
    }

    private fun getImageBytes(attrs: Map<String, Any>, key: String): ByteArray? {
        val v = attrs[key] ?: return null
        return when (v) {
            is ByteArray -> v
            is String -> try {
                android.util.Base64.decode(v, android.util.Base64.DEFAULT)
            } catch (_: Exception) { null }
            else -> null
        }
    }

    /** Build display name from given_name + family_name or resident_name or single name field. */
    private fun getName(attrs: Map<String, Any>): String {
        val given = getStr(attrs, "given_name", "given")
        val family = getStr(attrs, "family_name", "family_name")
        if (given.isNotBlank() || family.isNotBlank()) return "$given $family".trim()
        return getStr(attrs, "resident_name", "name", "full_name")
    }

    /** Build single-line address from address or street, building, district, state, pincode. */
    private fun getAddress(attrs: Map<String, Any>): String {
        val single = getStr(attrs, "address", "street_address")
        if (single.isNotBlank()) return single
        val parts = listOf(
            getStr(attrs, "building", "building_number"),
            getStr(attrs, "street", "street_name"),
            getStr(attrs, "district", "vtc"),
            getStr(attrs, "state", "state_province"),
            getStr(attrs, "pincode", "postal_code")
        ).filter { it.isNotBlank() }
        return parts.joinToString(", ")
    }

    fun fromParsed(parsed: ParsedMdoc): MdocCardData = fromAttributes(parsed.attributes)

    fun fromStringMap(fields: Map<String, String>): MdocCardData {
        val attrs = fields.mapValues { it.value as Any }
        return MdocCardData(
            name = getName(attrs),
            dateOfBirth = getStr(attrs, "birth_date", "date_of_birth", "dob"),
            gender = getStr(attrs, "gender", "sex"),
            address = getAddress(attrs),
            residentImageBytes = fields["resident_image"]?.let { s ->
                try { android.util.Base64.decode(s, android.util.Base64.DEFAULT) } catch (_: Exception) { null }
            }
        )
    }

    fun fromAttributes(attrs: Map<String, Any>): MdocCardData = MdocCardData(
        name = getName(attrs),
        dateOfBirth = getStr(attrs, "birth_date", "date_of_birth", "dob"),
        gender = getStr(attrs, "gender", "sex"),
        address = getAddress(attrs),
        residentImageBytes = getImageBytes(attrs, "resident_image")
    )
}
