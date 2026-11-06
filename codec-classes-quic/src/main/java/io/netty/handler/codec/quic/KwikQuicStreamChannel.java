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
import io.netty.channel.AbstractChannel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelMetadata;
import io.netty.channel.ChannelOutboundBuffer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.channel.EventLoop;
import io.netty.channel.RecvByteBufAllocator;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.channel.socket.ChannelInputShutdownReadComplete;
import io.netty.channel.socket.ChannelOutputShutdownException;
import io.netty.util.ReferenceCountUtil;
import org.jetbrains.annotations.Nullable;
import tech.kwik.core.QuicStream;
import tech.kwik.core.StreamListener;
import tech.kwik.core.StreamResetException;
import tech.kwik.core.StreamStoppedException;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;

/**
 * A {@link QuicStreamChannel} on a kwik stream, using its non-blocking API. Everything runs on the event loop, which is
 * also where kwik runs the connection and calls the {@link StreamListener}.
 */
final class KwikQuicStreamChannel extends AbstractChannel implements QuicStreamChannel {

    private static final ChannelMetadata METADATA = new ChannelMetadata(false, 16);
    // The messages Netty's quiche based stream channel uses, which applications (e.g. jvm-libp2p) match on
    static final String STOP_SENDING_MESSAGE = "STOP_SENDING frame received";
    static final String FIN_SENT_MESSAGE = "Fin was sent already";

    private final KwikQuicChannel parent;
    private final QuicStream stream;
    private final boolean localCreated;
    private final QuicStreamAddress address;
    private final KwikQuicStreamChannelConfig config;
    private boolean active = true;
    private boolean inputShutdown;
    private boolean outputShutdown;
    private boolean inputShutdownHandled;
    // Bytes written to the channel but not yet to the kwik stream
    private long pendingBytes;
    private boolean writable = true;
    @Nullable private volatile QuicStreamPriority priority;
    private boolean readPending;
    private boolean inRead;
    // Set when the remote reset the stream or stopped reading, failing what is written later
    @Nullable private Throwable writeFailure;

    KwikQuicStreamChannel(KwikQuicChannel parent, QuicStream stream, boolean localCreated) {
        super(parent);
        this.parent = parent;
        this.stream = stream;
        this.localCreated = localCreated;
        this.address = new QuicStreamAddress(stream.getStreamId());
        this.config = new KwikQuicStreamChannelConfig(this);
        // Local unidirectional streams will never receive data
        if (localCreated && stream.isUnidirectional()) {
            inputShutdown = true;
        }
        stream.setStreamListener(new StreamListener() {
            @Override
            public void readable(QuicStream s) {
                if (readPending || config.isAutoRead()) {
                    readFromStream();
                }
            }

            @Override
            public void writable(QuicStream s) {
                if (isOpen()) {
                    // Writes that did not fit are still in the outbound buffer
                    ((StreamUnsafe) unsafe()).resumeWrites();
                }
            }
        });
    }

    @Override
    public QuicChannel parent() {
        return parent;
    }

    @Override
    public QuicStreamAddress localAddress() {
        return address;
    }

    @Override
    public QuicStreamAddress remoteAddress() {
        return address;
    }

    @Override
    public boolean isLocalCreated() {
        return localCreated;
    }

    @Override
    public QuicStreamType type() {
        return stream.isUnidirectional()? QuicStreamType.UNIDIRECTIONAL: QuicStreamType.BIDIRECTIONAL;
    }

    @Override
    public long streamId() {
        return stream.getStreamId();
    }

    @Override
    @Nullable
    public QuicStreamPriority priority() {
        return priority;
    }

    @Override
    public ChannelFuture updatePriority(QuicStreamPriority priority, ChannelPromise promise) {
        // Only kept: kwik does not prioritise streams
        runOnLoop(() -> {
            this.priority = priority;
            promise.setSuccess();
        });
        return promise;
    }

    @Override
    public boolean isInputShutdown() {
        return inputShutdown;
    }

    @Override
    public boolean isOutputShutdown() {
        return outputShutdown;
    }

    @Override
    public boolean isShutdown() {
        return inputShutdown && outputShutdown;
    }

    @Override
    public ChannelFuture shutdownOutput(ChannelPromise promise) {
        return shutdownOutput(0, promise);
    }

    @Override
    public ChannelFuture shutdownInput(int error, ChannelPromise promise) {
        runOnLoop(() -> {
            if (!inputShutdown) {
                inputShutdown = true;
                stream.abortReading(error);
            }
            promise.setSuccess();
            closeIfDone();
        });
        return promise;
    }

    @Override
    public ChannelFuture shutdownOutput(int error, ChannelPromise promise) {
        runOnLoop(() -> {
            if (outputShutdown) {
                promise.setFailure(new ChannelOutputShutdownException(FIN_SENT_MESSAGE));
                return;
            }
            if (!isOpen()) {
                promise.setFailure(new ClosedChannelException());
                return;
            }
            outputShutdown = true;
            try {
                if (error == 0) {
                    // Data still waiting in the outbound buffer is written first, as quiche's channel does
                    flush();
                    stream.write(ByteBuffer.allocate(0), true);
                }
                else {
                    stream.resetStream(error);
                }
                promise.setSuccess();
            }
            catch (IOException e) {
                promise.setFailure(toChannelException(e));
            }
            closeIfDone();
        });
        return promise;
    }

    @Override
    public ChannelFuture shutdown(ChannelPromise promise) {
        return shutdown(0, promise);
    }

    @Override
    public ChannelFuture shutdown(int error, ChannelPromise promise) {
        ChannelPromise outputPromise = newPromise();
        shutdownInput(error, newPromise());
        shutdownOutput(error, outputPromise);
        outputPromise.addListener(f -> {
            if (f.isSuccess()) {
                promise.setSuccess();
            }
            else {
                promise.setFailure(f.cause());
            }
        });
        return promise;
    }

    @Override
    public KwikQuicStreamChannelConfig config() {
        return config;
    }

    @Override
    public boolean isOpen() {
        return active;
    }

    @Override
    public boolean isActive() {
        return active;
    }

    @Override
    public ChannelMetadata metadata() {
        return METADATA;
    }

    @Override
    public QuicStreamChannel read() {
        super.read();
        return this;
    }

    @Override
    public QuicStreamChannel flush() {
        super.flush();
        return this;
    }

    @Override
    protected AbstractUnsafe newUnsafe() {
        return new StreamUnsafe();
    }

    @Override
    protected boolean isCompatible(EventLoop loop) {
        // kwik runs the connection on the event loop of the QuicChannel, so the stream must use it too
        return loop == parent.eventLoop();
    }

    @Override
    protected SocketAddress localAddress0() {
        return address;
    }

    @Override
    protected SocketAddress remoteAddress0() {
        return address;
    }

    @Override
    protected void doRegister() throws Exception {
        super.doRegister();
        // Data may have arrived before the stream channel existed
        eventLoop().execute(() -> {
            if (config.isAutoRead()) {
                readFromStream();
            }
        });
    }

    @Override
    protected void doBind(SocketAddress localAddress) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void doDisconnect() {
        doClose();
    }

    @Override
    protected void doClose() {
        if (!active) {
            return;
        }
        active = false;
        pendingBytes = 0;
        boolean writable = !stream.isUnidirectional() || localCreated;
        boolean readable = !stream.isUnidirectional() || !localCreated;
        // As quiche's channel does: end the stream gracefully where it was not ended already
        if (!outputShutdown && writable) {
            outputShutdown = true;
            try {
                stream.write(ByteBuffer.allocate(0), true);
            }
            catch (IOException ignored) {
                // Already reset or closed
            }
        }
        if (!inputShutdown && readable) {
            inputShutdown = true;
            stream.abortReading(0);
        }
        stream.setStreamListener(null);
        parent.streamClosed(this);
    }

    @Override
    protected void doBeginRead() {
        readPending = true;
        if (!inRead) {
            readFromStream();
        }
    }

    @Override
    protected void doWrite(ChannelOutboundBuffer in) throws Exception {
        try {
            write(in);
        }
        finally {
            updateWritability();
        }
    }

    private void write(ChannelOutboundBuffer in) {
        for (;;) {
            Object msg = in.current();
            if (msg == null) {
                return;
            }
            if (writeFailure != null) {
                pendingBytes -= readableBytes(msg);
                in.remove(writeFailure);
                continue;
            }
            if (outputShutdown) {
                pendingBytes -= readableBytes(msg);
                in.remove(new ChannelOutputShutdownException(FIN_SENT_MESSAGE));
                continue;
            }
            ByteBuf data;
            boolean fin;
            if (msg instanceof QuicStreamFrame) {
                data = ((QuicStreamFrame) msg).content();
                fin = ((QuicStreamFrame) msg).hasFin();
            }
            else {
                data = (ByteBuf) msg;
                fin = false;
            }
            int readable = data.readableBytes();
            try {
                ByteBuffer source = data.nioBuffer();
                int written = stream.write(source, fin);
                pendingBytes -= written;
                data.skipBytes(written);
                in.progress(written);
                if (written < readable) {
                    // The rest when the stream is writable again (see the listener)
                    return;
                }
                if (fin) {
                    outputShutdown = true;
                }
                in.remove();
            }
            catch (IOException e) {
                pendingBytes -= data.readableBytes();
                Throwable failure = toChannelException(e);
                if (e instanceof StreamStoppedException) {
                    writeFailure = failure;
                }
                in.remove(failure);
                if (e instanceof StreamStoppedException) {
                    // As quiche's channel: report it, but leave the channel open, as the input may still deliver data
                    pipeline().fireExceptionCaught(failure);
                }
            }
        }
    }

    @Override
    protected Object filterOutboundMessage(Object msg) throws Exception {
        if (outputShutdown) {
            ReferenceCountUtil.release(msg);
            throw new ChannelOutputShutdownException(FIN_SENT_MESSAGE);
        }
        if (!localCreated && stream.isUnidirectional()) {
            ReferenceCountUtil.release(msg);
            throw new UnsupportedOperationException(
                    "Writes on non-local created streams that are unidirectional are not supported");
        }
        if (msg instanceof ByteBuf || msg instanceof QuicStreamFrame) {
            pendingBytes += readableBytes(msg);
            updateWritability();
            return msg;
        }
        ReferenceCountUtil.release(msg);
        throw new UnsupportedOperationException("unsupported message type: " + msg.getClass().getName());
    }

    private static int readableBytes(Object msg) {
        return msg instanceof ByteBuf? ((ByteBuf) msg).readableBytes(): ((QuicStreamFrame) msg).content().readableBytes();
    }

    /**
     * As with quiche: the space the stream has for data (here kwik's send buffer), less what is waiting to go into it.
     */
    @Override
    public long bytesBeforeUnwritable() {
        if (!isOpen() || outputShutdown || !localCreated && stream.isUnidirectional()) {
            return 0;
        }
        return Math.max(0, stream.writeCapacity() - pendingBytes);
    }

    @Override
    public boolean isWritable() {
        return bytesBeforeUnwritable() > 0;
    }

    private void updateWritability() {
        boolean now = isWritable();
        if (now != writable) {
            writable = now;
            pipeline().fireChannelWritabilityChanged();
        }
    }

    private void readFromStream() {
        if (!isOpen() || inputShutdown || inRead) {
            return;
        }
        inRead = true;
        ChannelPipeline pipeline = pipeline();
        RecvByteBufAllocator.Handle allocHandle = unsafe().recvBufAllocHandle();
        allocHandle.reset(config);
        boolean readSomething = false;
        try {
            do {
                ByteBuf buffer = allocHandle.allocate(config.getAllocator());
                int read;
                try {
                    allocHandle.attemptedBytesRead(buffer.writableBytes());
                    ByteBuffer target = buffer.nioBuffer(buffer.writerIndex(), buffer.writableBytes());
                    read = stream.read(target);
                }
                catch (StreamResetException reset) {
                    buffer.release();
                    inputShutdown = true;
                    pipeline.fireExceptionCaught(new QuicStreamResetException(reset.getMessage(), reset.getErrorCode()));
                    break;
                }
                catch (IOException closed) {
                    buffer.release();
                    inputShutdown = true;
                    break;
                }
                if (read <= 0) {
                    buffer.release();
                    if (read < 0) {
                        inputEnded();
                    }
                    break;
                }
                buffer.writerIndex(buffer.writerIndex() + read);
                allocHandle.lastBytesRead(read);
                allocHandle.incMessagesRead(1);
                readPending = false;
                readSomething = true;
                if (config.isReadFrames()) {
                    pipeline.fireChannelRead(new DefaultQuicStreamFrame(buffer, false));
                }
                else {
                    pipeline.fireChannelRead(buffer);
                }
            } while (allocHandle.continueReading() && isOpen());
        }
        finally {
            inRead = false;
            // Only for reads that found something: an empty one would shrink the allocator's next guess, which quiche
            // (that only reads when there is data) does not do
            if (readSomething) {
                allocHandle.readComplete();
            }
            if (readSomething || inputShutdown) {
                pipeline.fireChannelReadComplete();
            }
            if (inputShutdown && active && !inputShutdownHandled) {
                inputShutdownHandled = true;
                if (config.isAllowHalfClosure()) {
                    pipeline.fireUserEventTriggered(ChannelInputShutdownReadComplete.INSTANCE);
                    closeIfDone();
                }
                else {
                    unsafe().close(voidPromise());
                }
            }
        }
    }

    private void inputEnded() {
        inputShutdown = true;
        if (config.isReadFrames()) {
            pipeline().fireChannelRead(QuicStreamFrame.EMPTY_FIN);
        }
        if (config.isAllowHalfClosure()) {
            pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);
        }
    }

    private void closeIfDone() {
        if (active && inputShutdown && outputShutdown) {
            unsafe().close(voidPromise());
        }
    }

    private Throwable toChannelException(IOException e) {
        if (e instanceof StreamStoppedException) {
            return new ChannelOutputShutdownException(STOP_SENDING_MESSAGE, e);
        }
        if (outputShutdown) {
            return new ChannelOutputShutdownException(FIN_SENT_MESSAGE, e);
        }
        return e;
    }

    private void runOnLoop(Runnable task) {
        if (eventLoop().inEventLoop()) {
            task.run();
        }
        else {
            eventLoop().execute(task);
        }
    }

    /**
     * The connection closed: the stream can no longer be used.
     */
    void connectionClosed() {
        inputShutdown = true;
        outputShutdown = true;
        if (active) {
            unsafe().close(voidPromise());
        }
    }

    private final class StreamUnsafe extends AbstractUnsafe {
        void resumeWrites() {
            flush0();
            updateWritability();
        }

        @Override
        public void connect(SocketAddress remote, @Nullable SocketAddress local, ChannelPromise promise) {
            promise.setFailure(new UnsupportedOperationException());
        }
    }
}
