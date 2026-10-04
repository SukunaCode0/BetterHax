package dev.sora.protohax.relay.netty.channel

import io.netty.channel.Channel
import io.netty.channel.ChannelOption
import io.netty.channel.DefaultChannelConfig
import java.net.InetSocketAddress

/**
 * Custom channel configuration for native RakNet connections.
 * This configuration stores protocol version and target address separately
 * from the standard Netty options to avoid incompatibility issues.
 */
class NativeRakConfig(channel: Channel?) : DefaultChannelConfig(channel) {

    var targetAddress: InetSocketAddress? = null
    var protocolVersion = 0

    override fun getOptions(): Map<ChannelOption<*>, Any> {
        // Return only the standard Netty options, not RakNet-specific ones
        // Custom options (protocol version, target address) are stored as fields
        return super.getOptions()
    }

    override fun <T> getOption(option: ChannelOption<T>): T {
        return super.getOption(option)
    }

    override fun <T> setOption(option: ChannelOption<T>, value: T): Boolean {
        // All standard Netty options are handled by parent class
        return super.setOption(option, value)
    }

    companion object {
        /**
         * Custom channel option for storing the native RakNet target address.
         * This is NOT a RakChannelOption - it's our own custom option.
         */
        val RAK_NATIVE_TARGET_ADDRESS: ChannelOption<InetSocketAddress> = 
            ChannelOption.valueOf("RAK_NATIVE_TARGET_ADDRESS")
    }
}
