package com.github.ssogon.cryptographer

import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class Cryptographer {
    private val cipherTransformation: String
    private val useIv: Boolean
    private val key: Key
    private val iv: AlgorithmParameterSpec?

    private constructor(cipherTransformation: String, useIv: Boolean, key: Key) {
        this.cipherTransformation = cipherTransformation
        this.useIv = useIv
        this.key = key
        this.iv = null
    }

    private constructor(
        cipherTransformation: String,
        useIv: Boolean,
        key: Key,
        iv: AlgorithmParameterSpec
    ) {
        this.cipherTransformation = cipherTransformation
        this.useIv = useIv
        this.key = key
        this.iv = iv
    }

    fun encrypt(bytes: ByteArray): EncodableBytes {
        try {
            val cipher = Cipher.getInstance(cipherTransformation)
            if (useIv) {
                cipher.init(Cipher.ENCRYPT_MODE, key, iv)
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key)
            }
            val encryptedBytes = cipher.doFinal(bytes)
            return EncodableBytes(encryptedBytes)
        } catch (exception: Exception) {
            throw EncryptionException(exception)
        }
    }

    fun encrypt(@Suppress("SpellCheckingInspection") encodableBytes: EncodableBytes) = encrypt(encodableBytes.bytes)

    fun decrypt(bytes: ByteArray): EncodableBytes {
        try {
            val cipher = Cipher.getInstance(cipherTransformation)
            if (useIv) {
                cipher.init(Cipher.DECRYPT_MODE, key, iv)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key)
            }
            val decryptedBytes = cipher.doFinal(bytes)
            return EncodableBytes(decryptedBytes)
        } catch (exception: Exception) {
            throw DecryptionException(exception)
        }
    }

    fun decrypt(@Suppress("SpellCheckingInspection") encodableBytes: EncodableBytes) = decrypt(encodableBytes.bytes)

    companion object {
        private fun of(
            cipherAlgorithm: CipherAlgorithm,
            feedbackMode: FeedbackMode,
            paddingScheme: PaddingScheme,
            key: Key
        ): Cryptographer {
            val cipherTransformation =
                String.format("%s/%s/%s", cipherAlgorithm.identifier, feedbackMode.identifier, paddingScheme.identifier)
            return Cryptographer(cipherTransformation, feedbackMode.useIv, key)
        }

        private fun of(
            cipherAlgorithm: CipherAlgorithm,
            feedbackMode: FeedbackMode,
            paddingScheme: PaddingScheme,
            key: Key,
            iv: AlgorithmParameterSpec
        ): Cryptographer {
            val cipherTransformation =
                String.format("%s/%s/%s", cipherAlgorithm.identifier, feedbackMode.identifier, paddingScheme.identifier)
            return Cryptographer(cipherTransformation, feedbackMode.useIv, key, iv)
        }

        fun aes(key: Key): AesModeStep = CryptographerBuilder(CipherAlgorithm.AES, key)

        fun des(key: Key): DesModeStep = CryptographerBuilder(CipherAlgorithm.DES, key)

        fun desEde(key: Key): DesEdeModeStep = CryptographerBuilder(CipherAlgorithm.DES_EDE, key)

        fun rsa(key: Key): RsaModeStep = CryptographerBuilder(CipherAlgorithm.RSA, key)
    }

    interface AesModeStep {
        fun cbc(iv: IvParameterSpec): CbcPaddingStep
        fun ecb(): EcbPaddingStep
        fun gcm(iv: GCMParameterSpec): GcmPaddingStep
    }

    interface DesModeStep {
        fun cbc(iv: IvParameterSpec): CbcPaddingStep
        fun ecb(): EcbPaddingStep
    }

    interface DesEdeModeStep {
        fun cbc(iv: IvParameterSpec): CbcPaddingStep
        fun ecb(): EcbPaddingStep
    }

    interface RsaModeStep {
        fun ecb(): RsaEcbPaddingStep
    }

    interface CbcPaddingStep {
        fun noPadding(): Cryptographer
        fun pkcs5Padding(): Cryptographer
    }

    interface EcbPaddingStep {
        fun noPadding(): Cryptographer
        fun pkcs5Padding(): Cryptographer
    }

    interface GcmPaddingStep {
        fun noPadding(): Cryptographer
    }

    interface RsaEcbPaddingStep {
        fun pkcs1Padding(): Cryptographer
        fun oaepWithSha1AndMgf1Padding(): Cryptographer
        fun oaepWithSha256AndMgf1Padding(): Cryptographer
    }

    class CryptographerBuilder internal constructor(private val cipherAlgorithm: CipherAlgorithm, private val key: Key) :
        AesModeStep,
        DesModeStep,
        DesEdeModeStep,
        RsaModeStep,
        CbcPaddingStep,
        EcbPaddingStep,
        GcmPaddingStep,
        RsaEcbPaddingStep {
        private lateinit var feedbackMode: FeedbackMode
        private lateinit var iv: AlgorithmParameterSpec

        override fun cbc(iv: IvParameterSpec): CbcPaddingStep {
            this.feedbackMode = FeedbackMode.CBC
            this.iv = iv
            return this
        }

        override fun ecb(): CryptographerBuilder {
            this.feedbackMode = FeedbackMode.ECB
            return this
        }

        override fun gcm(iv: GCMParameterSpec): GcmPaddingStep {
            this.feedbackMode = FeedbackMode.GCM
            this.iv = iv
            return this
        }

        override fun noPadding() = if (feedbackMode.useIv) of(
            cipherAlgorithm,
            feedbackMode,
            PaddingScheme.NO_PADDING,
            key,
            iv
        ) else of(cipherAlgorithm, feedbackMode, PaddingScheme.NO_PADDING, key)

        override fun pkcs5Padding() = if (feedbackMode.useIv) of(
            cipherAlgorithm,
            feedbackMode,
            PaddingScheme.PKCS5_PADDING,
            key,
            iv
        ) else of(cipherAlgorithm, feedbackMode, PaddingScheme.PKCS5_PADDING, key)

        override fun pkcs1Padding() = of(cipherAlgorithm, feedbackMode, PaddingScheme.PKCS1_PADDING, key)

        override fun oaepWithSha1AndMgf1Padding() =
            of(cipherAlgorithm, feedbackMode, PaddingScheme.OAEP_WITH_SHA1_AND_MGF1_PADDING, key)

        override fun oaepWithSha256AndMgf1Padding() =
            of(cipherAlgorithm, feedbackMode, PaddingScheme.OAEP_WITH_SHA256_AND_MGF1_PADDING, key)
    }
}
