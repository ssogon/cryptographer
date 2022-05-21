package com.github.ssogon.cryptographer

internal enum class PaddingScheme(val identifier: String) {
    NO_PADDING("NoPadding"),
    PKCS5_PADDING("PKCS5Padding"),
    PKCS1_PADDING("PKCS1Padding"),
    OAEP_WITH_SHA1_AND_MGF1_PADDING("OAEPWithSHA-1AndMGF1Padding"),
    OAEP_WITH_SHA256_AND_MGF1_PADDING("OAEPWithSHA-256AndMGF1Padding"),
}
