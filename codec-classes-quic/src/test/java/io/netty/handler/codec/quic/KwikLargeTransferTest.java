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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ImmediateEventExecutor;
import io.netty.util.concurrent.Promise;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Transfers larger than the flow control windows, in both directions, with jvm-libp2p's QUIC settings.
 */
public class KwikLargeTransferTest extends AbstractQuicTest {

    private static final int SIZE = 4 * 1024 * 1024;

    private static <B extends QuicCodecBuilder<B>> B libp2p(B builder) {
        return builder.maxIdleTimeout(30_000, TimeUnit.MILLISECONDS)
                .initialMaxData(15L * 1024 * 1024)
                .initialMaxStreamsBidirectional(256)
                .initialMaxStreamDataBidirectionalRemote(10L * 1024 * 1024)
                .initialMaxStreamDataBidirectionalLocal(10L * 1024 * 1024)
                .initialMaxStreamsUnidirectional(0)
                .activeMigration(false);
    }

    @Test
    @Timeout(30)
    public void testEchoLargerThanWindows() throws Throwable {
        for (int round = 0; round < 3; round++) {
            echo(1, SIZE);
        }
    }

    @Test
    @Timeout(60)
    public void testConcurrentEchoesLargerThanConnectionWindow() throws Throwable {
        echo(20, 2 * 1024 * 1024);
    }

    @Test
    @Timeout(60)
    public void testActiveConnectionOutlivesIdleTimeout() throws Throwable {
        Channel server = QuicTestUtils.newServer(QuicTestUtils.newQuicServerBuilder(ImmediateEventExecutor.INSTANCE)
                        .maxIdleTimeout(5_000, TimeUnit.MILLISECONDS),
                InsecureQuicTokenHandler.INSTANCE, new ChannelInboundHandlerAdapter() {
                    @Override
                    public boolean isSharable() {
                        return true;
                    }
                }, new ChannelInboundHandlerAdapter() {
                    @Override
                    public boolean isSharable() {
                        return true;
                    }

                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) {
                        ctx.writeAndFlush(msg);
                    }
                });
        Channel channel = QuicTestUtils.newClient(QuicTestUtils.newQuicClientBuilder(ImmediateEventExecutor.INSTANCE)
                .maxIdleTimeout(5_000, TimeUnit.MILLISECONDS));
        try {
            QuicChannel quicChannel = QuicTestUtils.newQuicChannelBootstrap(channel)
                    .handler(new ChannelInboundHandlerAdapter())
                    .streamHandler(new ChannelInboundHandlerAdapter())
                    .remoteAddress(server.localAddress())
                    .connect().get();
            AtomicLong received = new AtomicLong();
            QuicStreamChannel stream = quicChannel.createStream(QuicStreamType.BIDIRECTIONAL,
                    new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelRead(ChannelHandlerContext ctx, Object msg) {
                            received.addAndGet(((ByteBuf) msg).readableBytes());
                            ReferenceCountUtil.release(msg);
                        }
                    }).sync().getNow();
            long end = System.currentTimeMillis() + 15_000;
            int sent = 0;
            while (System.currentTimeMillis() < end) {
                stream.writeAndFlush(Unpooled.wrappedBuffer(new byte[100])).sync();
                sent += 100;
                Thread.sleep(500);
            }
            Thread.sleep(500);
            assertEquals(sent, received.get());
            org.junit.jupiter.api.Assertions.assertTrue(quicChannel.isActive(), "connection closed while active");
            quicChannel.close().sync();
        } finally {
            server.close().sync();
            channel.close().sync();
        }
    }

    private void echo(int streams, int size) throws Throwable {
        Channel server = QuicTestUtils.newServer(libp2p(QuicTestUtils.newQuicServerBuilder(ImmediateEventExecutor.INSTANCE)),
                InsecureQuicTokenHandler.INSTANCE, new ChannelInboundHandlerAdapter() {
                    @Override
                    public boolean isSharable() {
                        return true;
                    }
                }, new ChannelInboundHandlerAdapter() {
                    @Override
                    public boolean isSharable() {
                        return true;
                    }

                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) {
                        ctx.write(msg);
                    }

                    @Override
                    public void channelReadComplete(ChannelHandlerContext ctx) {
                        ctx.flush();
                    }
                });
        Channel channel = QuicTestUtils.newClient(libp2p(QuicTestUtils.newQuicClientBuilder(ImmediateEventExecutor.INSTANCE)));
        try {
            QuicChannel quicChannel = QuicTestUtils.newQuicChannelBootstrap(channel)
                    .handler(new ChannelInboundHandlerAdapter())
                    .streamHandler(new ChannelInboundHandlerAdapter())
                    .remoteAddress(server.localAddress())
                    .connect().get();
            java.util.List<Promise<Long>> all = new java.util.ArrayList<>();
            for (int n = 0; n < streams; n++) {
                Promise<Long> done = ImmediateEventExecutor.INSTANCE.newPromise();
                all.add(done);
                AtomicLong received = new AtomicLong();
                QuicStreamChannel stream = quicChannel.createStream(QuicStreamType.BIDIRECTIONAL,
                        new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                if (received.addAndGet(((ByteBuf) msg).readableBytes()) == size) {
                                    done.trySuccess(received.get());
                                }
                                ReferenceCountUtil.release(msg);
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                done.tryFailure(cause);
                            }
                        }).sync().getNow();
                // In 64KiB writes, as an HTTP body would be
                for (int sent = 0; sent < size; sent += 65536) {
                    stream.write(Unpooled.wrappedBuffer(new byte[65536]));
                }
                stream.flush();
            }
            for (Promise<Long> done : all) {
                assertEquals(size, done.get(40, TimeUnit.SECONDS));
            }
            quicChannel.close().sync();
        } finally {
            server.close().sync();
            channel.close().sync();
        }
    }
}
