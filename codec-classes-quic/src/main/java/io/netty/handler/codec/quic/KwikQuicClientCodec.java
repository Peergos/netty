/*
 * Copyright 2020 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.codec.quic;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.socket.DatagramPacket;
import org.jetbrains.annotations.Nullable;

import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import tech.kwik.core.socket.DatagramEndpoint;

/**
 * The client codec: the kwik {@link DatagramEndpoint} of the UDP channel this handler is in, which the
 * {@link KwikQuicChannel}s created by {@link QuicChannel#newBootstrap} connect through.
 */
final class KwikQuicClientCodec extends ChannelDuplexHandler {

    private final KwikConfig config;
    private final int localConnIdLength;
    @Nullable private DatagramEndpoint endpoint;
    private final Set<KwikQuicChannel> channels = new HashSet<>();

    KwikQuicClientCodec(KwikConfig config, int localConnIdLength) {
        this.config = config;
        this.localConnIdLength = localConnIdLength;
    }

    KwikConfig config() {
        return config;
    }

    @Override
    public boolean isSharable() {
        return false;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        endpoint = new DatagramEndpoint(new KwikDatagramSender(ctx, this::sendFailed), localConnIdLength == 0? 8: Integer.max(4, localConnIdLength));
    }

    DatagramEndpoint endpoint() {
        DatagramEndpoint e = endpoint;
        if (e == null) {
            throw new IllegalStateException("codec not added to a pipeline");
        }
        return e;
    }

    @Override
    public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress, SocketAddress localAddress,
                        ChannelPromise promise) {
        if (remoteAddress instanceof KwikQuicChannelAddress) {
            KwikQuicChannel channel = ((KwikQuicChannelAddress) remoteAddress).channel;
            QuicConnectionAddress requested = channel.requestedConnectionAddress;
            if (requested != null && requested != QuicConnectionAddress.EPHEMERAL && localConnIdLength > 0
                    && requested.id().remaining() > localConnIdLength) {
                promise.setFailure(new IllegalArgumentException("connection id longer than " + localConnIdLength));
                return;
            }
            try {
                channel.connectClient(this);
                channels.add(channel);
                channel.closeFuture().addListener(f -> channels.remove(channel));
                promise.setSuccess();
            }
            catch (Exception e) {
                promise.setFailure(e);
            }
        }
        else {
            ctx.connect(remoteAddress, localAddress, promise);
        }
    }

    private void sendFailed(InetSocketAddress destination, Throwable cause) {
        // An ICMP port unreachable for an earlier datagram, which a connected socket reports on a later send: the
        // peer may yet answer (e.g. a NAT that opens once the peer dials us), so the handshake carries on
        if (cause instanceof PortUnreachableException) {
            return;
        }
        for (KwikQuicChannel channel : new ArrayList<>(channels)) {
            channel.sendFailed(destination, cause);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DatagramPacket && endpoint != null) {
            DatagramPacket packet = (DatagramPacket) msg;
            try {
                if (!endpoint.receive(packet.content().nioBuffer(), packet.sender())) {
                    // Not for one of our connections
                    ctx.fireChannelRead(packet.retain());
                }
            }
            finally {
                packet.release();
            }
        }
        else {
            ctx.fireChannelRead(msg);
        }
    }
}
