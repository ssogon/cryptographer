package com.github.ssogon.cryptographer

internal enum class CipherAlgorithm(val identifier: String) {
    AES("AES"),
    DES("DES"),
    @Suppress("SpellCheckingInspection")
    DES_EDE("DESede"),
    RSA("RSA"),
}
