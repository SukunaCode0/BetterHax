package dev.sora.protohax.util

object SvcJournal {
    @Volatile var dir: java.io.File? = null
    fun mark(step: String) {
        try {
            val d = dir ?: return
            val stamp = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())
            java.io.File(d, "service.log").appendText(stamp + " " + step + "\n")
        } catch (_: Throwable) { }
    }
}
