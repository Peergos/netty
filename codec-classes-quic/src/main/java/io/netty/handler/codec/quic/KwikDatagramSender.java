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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import org.jetbrains.annotations.Nullable;
import tech.kwik.core.socket.DatagramSender;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.function.BiConsumer;

/**
 * Sends kwik's datagrams through the UDP channel the codec is in.
 */
final class KwikDatagramSender implements DatagramSender {

    private final ChannelHandlerContext ctx;
    @Nullable private final BiConsumer<InetSocketAddress, Throwable> sendFailed;

    KwikDatagramSender(ChannelHandlerContext ctx) {
        this(ctx, null);
    }

    /**
     * @param sendFailed called on the event loop with the destination of each datagram the channel failed to send
     */
    KwikDatagramSender(ChannelHandlerContext ctx, @Nullable BiConsumer<InetSocketAddress, Throwable> sendFailed) {
        this.ctx = ctx;
        this.sendFailed = sendFailed;
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress destination) {
        ByteBuffer source = data.duplicate();
        source.position(0);
        // kwik reuses its buffer once this returns
        ByteBuf copy = ctx.alloc().directBuffer(source.remaining());
        copy.writeBytes(source);
        // Not a void promise, which would fire a failed send (e.g. no route to the destination) through the pipeline
        // as an exception, once per datagram
        ChannelFuture sent = ctx.writeAndFlush(new DatagramPacket(copy, destination));
        if (sendFailed != null) {
            sent.addListener(f -> {
                if (!f.isSuccess()) {
                    sendFailed.accept(destination, f.cause());
                }
            });
        }
        return Instant.now();
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return (InetSocketAddress) ctx.channel().localAddress();
    }
}
