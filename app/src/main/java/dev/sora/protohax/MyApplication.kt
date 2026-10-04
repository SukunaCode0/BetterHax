package dev.sora.protohax

import android.annotation.SuppressLint
import android.app.Application
import dev.sora.protohax.relay.netty.log.NettyLoggerFactory
import dev.sora.protohax.relay.service.AppService
import dev.sora.protohax.ui.overlay.OverlayManager
import io.netty.util.internal.logging.InternalLoggerFactory

class MyApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        installCrashRecorder()

		InternalLoggerFactory.setDefaultFactory(NettyLoggerFactory())

		density = resources.displayMetrics.density

        instance = this
    }

    private fun installCrashRecorder() {
        val appDir = filesDir
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val sw = java.io.StringWriter()
                error.printStackTrace(java.io.PrintWriter(sw))
                val stamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date())
                java.io.File(appDir, "crash.log").appendText(stamp + " thread=" + thread.name + "\n" + sw.toString() + "\n")
            } catch (_: Throwable) { }
            if (prev != null) prev.uncaughtException(thread, error)
            else android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    companion object {
        lateinit var instance: MyApplication
            private set

		var density: Float = 1f
			private set

		@SuppressLint("StaticFieldLeak")
		val overlayManager = OverlayManager().also {
			AppService.addListener(it)
		}
    }
}
