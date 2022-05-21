package com.github.ssogon.cryptographer

import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import kotlin.test.assertEquals

const val PLAIN_TEXT = "plain_text"
const val PLAIN_TEXT_FOR_NO_PADDING = "plain_text______" // 16 bytes
const val AES_IV_SIZE_IN_BYTE = 16
const val AES_IV_SIZE_IN_BIT = AES_IV_SIZE_IN_BYTE * 8
const val DES_IV_SIZE_IN_BYTE = 8

internal class CryptographerTest {
    @Test
    fun aes_cbc_noPadding() {
        val cryptographer = Cryptographer.aes(generateAesKey())
            .cbc(generateAesIv())
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun aes_cbc_pkcs5Padding() {
        val cryptographer = Cryptographer.aes(generateAesKey())
            .cbc(generateAesIv())
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun aes_ecb_noPadding() {
        val cryptographer = Cryptographer.aes(generateAesKey())
            .ecb()
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun aes_ecb_pkcs5Padding() {
        val cryptographer = Cryptographer.aes(generateAesKey())
            .ecb()
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun aes_gcm_noPadding() {
        val cryptographer = Cryptographer.aes(generateAesKey())
            .gcm(generateAesGcmIv())
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun des_cbc_noPadding() {
        val cryptographer = Cryptographer.des(generateDesKey())
            .cbc(generateDesIv())
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun des_cbc_pkcs5Padding() {
        val cryptographer = Cryptographer.des(generateDesKey())
            .cbc(generateDesIv())
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun des_ecb_noPadding() {
        val cryptographer = Cryptographer.des(generateDesKey())
            .ecb()
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun des_ecb_pkcs5Padding() {
        val cryptographer = Cryptographer.des(generateDesKey())
            .ecb()
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun desEde_cbc_noPadding() {
        val cryptographer = Cryptographer.desEde(generateDesEdeKey())
            .cbc(generateDesIv())
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun desEde_cbc_pkcs5Padding() {
        val cryptographer = Cryptographer.desEde(generateDesEdeKey())
            .cbc(generateDesIv())
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun desEde_ecb_noPadding() {
        val cryptographer = Cryptographer.desEde(generateDesEdeKey())
            .ecb()
            .noPadding()

        val plainBytes = PLAIN_TEXT_FOR_NO_PADDING.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT_FOR_NO_PADDING, decryptedText)
    }

    @Test
    fun desEde_ecb_pkcs5Padding() {
        val cryptographer = Cryptographer.desEde(generateDesEdeKey())
            .ecb()
            .pkcs5Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cryptographer.encrypt(plainBytes)
        val decryptedBytes = cryptographer.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun rsa_ecb_pkcs1Padding() {
        val (publicKey, privateKey) = generateRsaKey()

        val encryptor = Cryptographer.rsa(publicKey)
            .ecb()
            .pkcs1Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = encryptor.encrypt(plainBytes)

        @Suppress("SpellCheckingInspection")
        val decryptor = Cryptographer.rsa(privateKey)
            .ecb()
            .pkcs1Padding()

        val decryptedBytes = decryptor.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun rsa_ecb_oaepWithSha1AndMgf1Padding() {
        val (publicKey, privateKey) = generateRsaKey()

        val encryptor = Cryptographer.rsa(publicKey)
            .ecb()
            .oaepWithSha1AndMgf1Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = encryptor.encrypt(plainBytes)

        @Suppress("SpellCheckingInspection")
        val decryptor = Cryptographer.rsa(privateKey)
            .ecb()
            .oaepWithSha1AndMgf1Padding()

        val decryptedBytes = decryptor.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    @Test
    fun rsa_ecb_oaepWithSha256AndMgf1Padding() {
        val (publicKey, privateKey) = generateRsaKey()

        val encryptor = Cryptographer.rsa(publicKey)
            .ecb()
            .oaepWithSha256AndMgf1Padding()

        val plainBytes = PLAIN_TEXT.toByteArray(Charsets.UTF_8)
        val encryptedBytes = encryptor.encrypt(plainBytes)

        @Suppress("SpellCheckingInspection")
        val decryptor = Cryptographer.rsa(privateKey)
            .ecb()
            .oaepWithSha256AndMgf1Padding()

        val decryptedBytes = decryptor.decrypt(encryptedBytes)
        val decryptedText = decryptedBytes.toUtf8()

        assertEquals(PLAIN_TEXT, decryptedText)
    }

    private operator fun KeyPair.component1(): PublicKey = public

    private operator fun KeyPair.component2(): PrivateKey = private

    private fun generateAesKey() = KeyGenerator.getInstance(CipherAlgorithm.AES.identifier).generateKey()

    private fun generateDesKey() = KeyGenerator.getInstance(CipherAlgorithm.DES.identifier).generateKey()

    private fun generateDesEdeKey() = KeyGenerator.getInstance(CipherAlgorithm.DES_EDE.identifier).generateKey()

    private fun generateRsaKey() = KeyPairGenerator.getInstance(CipherAlgorithm.RSA.identifier).generateKeyPair()

    private fun generateAesIv(): IvParameterSpec {
        val bytes = ByteArray(AES_IV_SIZE_IN_BYTE)
        SecureRandom().nextBytes(bytes)
        return IvParameterSpec(bytes)
    }

    private fun generateAesGcmIv(): GCMParameterSpec {
        val bytes = ByteArray(AES_IV_SIZE_IN_BIT)
        SecureRandom().nextBytes(bytes)
        return GCMParameterSpec(128, bytes)
    }

    private fun generateDesIv(): IvParameterSpec {
        val bytes = ByteArray(DES_IV_SIZE_IN_BYTE)
        SecureRandom().nextBytes(bytes)
        return IvParameterSpec(bytes)
    }
}
