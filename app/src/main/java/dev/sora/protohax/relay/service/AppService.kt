package dev.sora.protohax.relay.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.view.WindowManager
import androidx.core.app.NotificationCompat
import dev.sora.protohax.MyApplication
import dev.sora.protohax.R
import dev.sora.protohax.relay.MinecraftRelay
import dev.sora.protohax.ui.activities.MainActivity
import dev.sora.protohax.ui.components.screen.settings.Settings
import dev.sora.protohax.util.ContextUtils.getApplicationName
import dev.sora.relay.utils.logError
import dev.sora.relay.utils.logInfo
import libmitm.Libmitm
import libmitm.TUN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface


class AppService : VpnService() {

    private lateinit var windowManager: WindowManager

    private var vpnDescriptor: ParcelFileDescriptor? = null
    private var tun: TUN? = null

    override fun onCreate() {
        val notificationManager = getSystemService(Service.NOTIFICATION_SERVICE) as NotificationManager
        if (notificationManager.getNotificationChannel(CHANNEL_ID) == null) {
            notificationManager.createNotificationChannel(NotificationChannel(
                CHANNEL_ID, getString(
                    R.string.app_name
                ), NotificationManager.IMPORTANCE_LOW))
        }

        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager

		dev.sora.protohax.util.SvcJournal.mark("svc.onCreate")
		MyApplication.overlayManager.currentContext = this
    }

    override fun onDestroy() {
		dev.sora.protohax.util.SvcJournal.mark("svc.onDestroy")
		logInfo("VPN service destroyed")
		stopVPN()
		MyApplication.overlayManager.currentContext = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent ?: return START_NOT_STICKY

        val action = intent.action
        try {
            if (ACTION_START == action) {
                dev.sora.protohax.util.SvcJournal.mark("svc.start-cmd")
                startForeground(1, createNotification())
                try {
                    startVPN()
                } catch (t: Throwable) {
                    logError("startVPN", t)
                }
                dev.sora.protohax.util.SvcJournal.mark("svc.cmd-return isActive=" + isActive)
                if (!isActive) stopSelf()
            } else {
                stopVPN()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        } catch (t: Throwable) {
            logError("command", t)
        }
        return super.onStartCommand(intent, flags, startId)
    }

    private fun startVPN() {
        val (hasIPv4, hasIPv6) = when(Settings.ipv6Status.getValue(this)) {
			Settings.IPv6Choices.AUTOMATIC -> checkNetState()
			Settings.IPv6Choices.ENABLED -> true to true
			Settings.IPv6Choices.DISABLED -> true to false
			Settings.IPv6Choices.V6ONLY -> false to true
		}

        val builder = Builder()
        builder.setBlocking(true)
        builder.setMtu(VPN_MTU)
        builder.setSession("ProtoHax")
        builder.addAllowedApplication(MainActivity.targetPackage)
        builder.addDnsServer("8.8.8.8")
        // ipv4
        if (hasIPv4) {
            builder.addAddress(PRIVATE_VLAN4_CLIENT, 30)
            builder.addRoute("0.0.0.0", 0)
        }
        // ipv6
        if (hasIPv6) {
            builder.addAddress(PRIVATE_VLAN6_CLIENT, 126)
            builder.addRoute("::", 0)
        }

        val vpnDescriptor = try {
            builder.establish()
        } catch (t: Throwable) {
            logError("vpn establish", t)
            null
        } ?: run {
            logError("vpn establish returned null (permission revoked or another VPN active?)")
            dev.sora.protohax.util.SvcJournal.mark("vpn.establish.NULL")
            return
        }
        this.vpnDescriptor = vpnDescriptor
        dev.sora.protohax.util.SvcJournal.mark("vpn.established")

        dev.sora.protohax.util.SvcJournal.mark("tun.build-try")
        val vpnFd = try {
            vpnDescriptor.fileDescriptor
        } catch (t: Throwable) {
            reportTunFailure("tun.fd-fail", t)
            return
        }
        dev.sora.protohax.util.SvcJournal.mark("tun.fd-ok")
        val tun = try {
            TUN(java.io.FileInputStream(vpnFd), java.io.FileOutputStream(vpnFd)).apply {
                mtu = VPN_MTU
            }
        } catch (t: Throwable) {
            reportTunFailure("tun.build-fail", t)
            return
        }
        tun.logger = { dev.sora.protohax.util.SvcJournal.mark(it) }
        this.tun = tun
        dev.sora.protohax.util.SvcJournal.mark("tun.built")
        try {
            tun.start()
        } catch (t: Throwable) {
            reportTunFailure("tun.start-fail", t)
            return
        }
        dev.sora.protohax.util.SvcJournal.mark("tun.started")
        logInfo("netstack started")
        isActive = true
        try {
			MinecraftRelay.announceRelayUp()
            serviceListeners.forEach { it.onServiceStarted() }
            dev.sora.protohax.util.SvcJournal.mark("relay.up isActive=" + isActive)
        } catch (t: Throwable) {
            logError("start callback", t)
        }
    }

    private fun reportTunFailure(step: String, t: Throwable) {
        dev.sora.protohax.util.SvcJournal.mark(step + " " + t.javaClass.simpleName + ": " + (t.message ?: "null"))
        try {
            val sw = java.io.StringWriter()
            t.printStackTrace(java.io.PrintWriter(sw))
            val stamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date())
            java.io.File(filesDir, "crash.log").appendText(stamp + " tun-failure\n" + sw.toString() + "\n")
        } catch (_: Throwable) {
        }
        logError("tun", t)
    }

    private fun stopVPN() {
        isActive = false
		try {
			vpnDescriptor?.close()
		} catch (_: Throwable) {
		}
		tun?.let {
			try {
				serviceListeners.forEach { l -> l.onServiceStopped() }
			} catch (t: Throwable) {
				logError("stop callback", t)
			}
			Thread(it::close).start()
		}
    }

    private fun checkNetState(): Pair<Boolean, Boolean> {
		val connectivityManager = this.getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
		val activeNetwork = connectivityManager.getLinkProperties(connectivityManager.activeNetwork ?: return true to false) ?: return true to false
		val interfaceName = activeNetwork.interfaceName

		val networkInterfaces = NetworkInterface.getNetworkInterfaces()
		while (networkInterfaces.hasMoreElements()) {
			val ni = networkInterfaces.nextElement()
			if (ni.name != interfaceName) continue

			var hasIPv4 = false
			var hasIPv6 = false
			for (addr in ni.interfaceAddresses) {
				if (addr.address is Inet6Address) {
					hasIPv6 = true
				} else if (addr.address is Inet4Address) {
					hasIPv4 = true
				}
			}
			return hasIPv4 to hasIPv6
		}

		return true to false
    }

    private fun createNotification(): Notification {
        val flag = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT

        val intent = Intent(this, MainActivity::class.java)
        intent.addCategory(Intent.CATEGORY_LAUNCHER)
        intent.action = Intent.ACTION_MAIN
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, flag)

        val stopIntent = Intent(ACTION_STOP)
        stopIntent.setPackage(packageName)
        val pendingIntent1 = PendingIntent.getForegroundService(this, 1, stopIntent, flag)

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(
                R.string.proxy_notification, getString(R.string.app_name), packageManager.getApplicationName(MainActivity.targetPackage)))
            .setSmallIcon(R.drawable.notification_icon)
            .setLargeIcon(BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
            .setOngoing(true)
            .setContentIntent(pendingIntent)
			.addAction(R.drawable.notification_icon, getString(R.string.dashboard_fab_disconnect), pendingIntent1)

        return builder.build()
    }

    companion object {
        const val ACTION_START = "dev.sora.libmitm.vpn.start"
        const val ACTION_STOP = "dev.sora.libmitm.vpn.stop"
        const val CHANNEL_ID = "dev.sora.protohax.NOTIFICATION_CHANNEL_ID"

        const val VPN_MTU = 1500
        const val PRIVATE_VLAN4_CLIENT = "10.13.37.1"
        const val PRIVATE_VLAN6_CLIENT = "1337::1"

        var isActive = false
        private val serviceListeners = mutableSetOf<ServiceListener>()

        fun addListener(listener: ServiceListener) {
            serviceListeners.add(listener)
        }

        fun removeListener(listener: ServiceListener) {
            serviceListeners.remove(listener)
        }
    }
}
