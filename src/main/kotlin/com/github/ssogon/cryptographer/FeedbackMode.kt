package com.github.ssogon.cryptographer

internal enum class FeedbackMode(val identifier: String, val useIv: Boolean) {
    CBC("CBC", true),
    ECB("ECB", false),
    GCM("GCM", true),
}
