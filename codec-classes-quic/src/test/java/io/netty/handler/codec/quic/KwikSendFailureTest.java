/*
 * Copyright 2026 The Netty Project
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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ConnectTimeoutException;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.ImmediateEventExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A UDP channel that cannot send its datagrams, e.g. for want of a route to the peer.
 */
public class KwikSendFailureTest extends AbstractQuicTest {

    private static final InetSocketAddress PEER = new InetSocketAddress("127.0.0.1", 9);

    @Test
    @Timeout(10)
    public void testFailedSendFailsTheConnect() throws Throwable {
        IOException unreachable = new SocketException("Network is unreachable");
        List<Throwable> caught = new CopyOnWriteArrayList<>();
        Channel channel = clientFailingSendsWith(unreachable, caught);
        try {
            long start = System.nanoTime();
            Future<QuicChannel> connect = connect(channel, 5_000);
            assertTrue(connect.await(4, TimeUnit.SECONDS), "connect waited for its timeout");
            assertSame(unreachable, connect.cause());
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
            // any datagrams kwik still had to send
            Thread.sleep(500);
            assertEquals(List.of(), caught, "send failures fired through the pipeline");
        } finally {
            channel.close().sync();
        }
    }

    @Test
    @Timeout(10)
    public void testPortUnreachableLeavesTheConnectToItsTimeout() throws Throwable {
        List<Throwable> caught = new CopyOnWriteArrayList<>();
        Channel channel = clientFailingSendsWith(new PortUnreachableException(), caught);
        try {
            Future<QuicChannel> connect = connect(channel, 1_000);
            assertFalse(connect.await(500, TimeUnit.MILLISECONDS), "connect failed on a port unreachable");
            assertTrue(connect.await(5, TimeUnit.SECONDS));
            assertInstanceOf(ConnectTimeoutException.class, connect.cause());
            assertEquals(List.of(), caught, "send failures fired through the pipeline");
        } finally {
            channel.close().sync();
        }
    }

    private static Future<QuicChannel> connect(Channel channel, int timeoutMillis) {
        return QuicTestUtils.newQuicChannelBootstrap(channel)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeoutMillis)
                .handler(new ChannelInboundHandlerAdapter())
                .streamHandler(new ChannelInboundHandlerAdapter())
                .remoteAddress(PEER)
                .connect();
    }

    private static Channel clientFailingSendsWith(IOException failure, List<Throwable> caught) throws Exception {
        Channel channel = QuicTestUtils.newClient(QuicTestUtils.newQuicClientBuilder(ImmediateEventExecutor.INSTANCE));
        channel.pipeline().addFirst(new ChannelOutboundHandlerAdapter() {
            @Override
            public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
                if (msg instanceof DatagramPacket) {
                    ReferenceCountUtil.release(msg);
                    promise.setFailure(failure);
                } else {
                    ctx.write(msg, promise);
                }
            }
        });
        channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                caught.add(cause);
            }
        });
        return channel;
    }
}
