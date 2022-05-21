package com.github.ssogon.cryptographer

import java.nio.charset.StandardCharsets
import java.util.Base64

@Suppress("SpellCheckingInspection")
class EncodableBytes(val bytes: ByteArray) {
    fun toUsAscii() = String(bytes, StandardCharsets.US_ASCII)

    fun toIso88591() = String(bytes, StandardCharsets.ISO_8859_1)

    fun toUtf8() = String(bytes, StandardCharsets.UTF_8)

    fun toUtf16() = String(bytes, StandardCharsets.UTF_16)

    fun toUtf16Be() = String(bytes, StandardCharsets.UTF_16BE)

    fun toUtf16Le() = String(bytes, StandardCharsets.UTF_16LE)

    fun toBase64() = Base64.getEncoder().encodeToString(bytes)

    fun toBase64Url() = Base64.getUrlEncoder().encodeToString(bytes)

    fun toUpperHex() = bytesToHex(bytes).uppercase()

    fun toLowerHex() = bytesToHex(bytes)

    private companion object {
        fun bytesToHex(bytes: ByteArray): String {
            val stringBuffer = StringBuffer()
            for (byte in bytes) {
                stringBuffer.append(byteToHex(byte))
            }
            return stringBuffer.toString()
        }

        fun byteToHex(byte: Byte): String {
            val byteAsInt = byte.toInt()
            val charArray = CharArray(2)
            charArray[0] = Character.forDigit((byteAsInt shr 4) and 0xF, 16)
            charArray[1] = Character.forDigit((byteAsInt and 0xF), 16)
            return String(charArray)
        }
    }
}
