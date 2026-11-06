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
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelMetadata;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelOutboundBuffer;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ConnectTimeoutException;
import io.netty.channel.DefaultChannelPipeline;
import io.netty.channel.EventLoop;
import io.netty.channel.RecvByteBufAllocator;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.jetbrains.annotations.Nullable;
import tech.kwik.core.ConnectionListener;
import tech.kwik.core.ConnectionTerminatedEvent;
import tech.kwik.core.PeerClosedConnectionException;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.NullLogger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.net.SocketAddress;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ConnectionPendingException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * A {@link QuicChannel} on a kwik connection. kwik runs the connection on this channel's event loop (the event loop of
 * the UDP channel the codec is in), so all of it, including the kwik callbacks, happens on that thread.
 */
final class KwikQuicChannel extends AbstractChannel implements QuicChannel {

    private static final InternalLogger LOGGER = InternalLoggerFactory.getInstance(KwikQuicChannel.class);
    private static final ChannelMetadata METADATA = new ChannelMetadata(false, 16);

    private enum State { OPEN, ACTIVE, CLOSED }

    private final boolean server;
    private final KwikConfig quicConfig;
    private final KwikQuicChannelConfig config;
    private final KwikQuicSslEngine sslEngine;
    @Nullable private final ChannelHandler streamHandler;
    private final Map.Entry<ChannelOption<?>, Object>[] streamOptions;
    private final Map.Entry<AttributeKey<?>, Object>[] streamAttrs;
    private final Map<Integer, KwikQuicStreamChannel> streams = new HashMap<>();
    @Nullable private final InetSocketAddress localSocketAddress;
    private final InetSocketAddress remoteSocketAddress;
    @Nullable private QuicConnection connection;
    @Nullable private String applicationProtocol;
    private State state = State.OPEN;
    @Nullable private ChannelPromise connectPromise;
    // kwik chooses the connection ids; a requested one is only checked
    @Nullable QuicConnectionAddress requestedConnectionAddress;
    private boolean timedOut;
    private boolean closeEventFired;
    private final ArrayDeque<byte[]> datagrams = new ArrayDeque<>();
    private boolean readPending;
    private boolean inRead;

    private KwikQuicChannel(Channel parent, boolean server, KwikConfig quicConfig,
                            @Nullable InetSocketAddress localSocketAddress, InetSocketAddress remoteSocketAddress,
                            @Nullable ChannelHandler streamHandler, Map.Entry<ChannelOption<?>, Object>[] streamOptions,
                            Map.Entry<AttributeKey<?>, Object>[] streamAttrs) {
        super(parent);
        this.server = server;
        this.quicConfig = quicConfig;
        this.config = new KwikQuicChannelConfig(this);
        // As with quiche, the builder's provider gives each channel its engine (whose peer host, if any, the trust
        // manager checks)
        this.sslEngine = (KwikQuicSslEngine) quicConfig.sslEngineProvider.apply(this);
        this.localSocketAddress = localSocketAddress;
        this.remoteSocketAddress = remoteSocketAddress;
        this.streamHandler = streamHandler;
        this.streamOptions = streamOptions;
        this.streamAttrs = streamAttrs;
    }

    /**
     * A channel for a server connection whose handshake has finished; register it, and it becomes active.
     */
    static KwikQuicChannel forServer(Channel parent, KwikConfig quicConfig, QuicConnection connection,
                                     String applicationProtocol, InetSocketAddress remote,
                                     @Nullable ChannelHandler streamHandler,
                                     Map.Entry<ChannelOption<?>, Object>[] streamOptions,
                                     Map.Entry<AttributeKey<?>, Object>[] streamAttrs) {
        KwikQuicChannel channel = new KwikQuicChannel(parent, true, quicConfig, (InetSocketAddress) parent.localAddress(),
                remote, streamHandler, streamOptions, streamAttrs);
        channel.attach(connection, applicationProtocol);
        return channel;
    }

    static KwikQuicChannel forClient(Channel parent, KwikConfig quicConfig, InetSocketAddress local,
                                     InetSocketAddress remote, @Nullable ChannelHandler streamHandler,
                                     Map.Entry<ChannelOption<?>, Object>[] streamOptions,
                                     Map.Entry<AttributeKey<?>, Object>[] streamAttrs) {
        return new KwikQuicChannel(parent, false, quicConfig, local, remote, streamHandler, streamOptions, streamAttrs);
    }

    private void attach(QuicConnection connection, @Nullable String applicationProtocol) {
        this.connection = connection;
        this.applicationProtocol = applicationProtocol;
        connection.setConnectionListener(new ConnectionListener() {
            @Override
            public void disconnected(ConnectionTerminatedEvent event) {
                // A task, so datagrams kwik handed over before the close are delivered first
                eventLoopExecutor().execute(() -> connectionTerminated(event));
            }
        });
        if (quicConfig.datagramRecvQueueLen > 0) {
            connection.setDatagramHandler(this::datagramReceived, eventLoopExecutor());
        }
        connection.setStreamCreditListener(() -> runOnLoop(() -> {
            if (state == State.ACTIVE) {
                pipeline().fireUserEventTriggered(QuicStreamLimitChangedEvent.INSTANCE);
            }
        }));
        if (!server) {
            connection.setPeerInitiatedStreamCallback(stream -> runOnLoop(() -> peerInitiatedStream(stream)));
        }
    }

    /**
     * Called (on the event loop) once the handshake has finished, for a channel registered in an active state.
     */
    void handshakeCompleted() {
        if (state != State.OPEN) {
            return;
        }
        state = State.ACTIVE;
        sslEngine.handshakeFinished(connection != null? connection.getPeerCertificateChain(): null, applicationProtocol);
        fireDatagramExtensionEvent();
        pipeline().fireChannelActive();
        pipeline().fireUserEventTriggered(SslHandshakeCompletionEvent.SUCCESS);
        pipeline().fireUserEventTriggered(QuicStreamLimitChangedEvent.INSTANCE);
    }

    private void fireDatagramExtensionEvent() {
        QuicConnection conn = connection;
        if (conn != null && conn.isDatagramExtensionEnabled()) {
            pipeline().fireUserEventTriggered(new QuicDatagramExtensionEvent(conn.maxDatagramDataSize()));
        }
    }

    private java.util.concurrent.ExecutorService eventLoopExecutor() {
        Channel p = parent();
        return p != null? p.eventLoop(): eventLoop();
    }

    private void datagramReceived(byte[] data) {
        if (state == State.CLOSED) {
            return;
        }
        if (datagrams.size() >= quicConfig.datagramRecvQueueLen) {
            datagrams.poll();
        }
        datagrams.add(data);
        if (state == State.ACTIVE && (readPending || config().isAutoRead())) {
            readDatagrams();
        }
    }

    private void readDatagrams() {
        if (inRead || datagrams.isEmpty()) {
            return;
        }
        inRead = true;
        try {
            RecvByteBufAllocator.Handle allocHandle = unsafe().recvBufAllocHandle();
            allocHandle.reset(config());
            do {
                byte[] data = datagrams.poll();
                if (data == null) {
                    break;
                }
                readPending = false;
                allocHandle.lastBytesRead(data.length);
                allocHandle.incMessagesRead(1);
                pipeline().fireChannelRead(alloc().directBuffer(data.length).writeBytes(data));
            } while (allocHandle.continueReading());
            allocHandle.readComplete();
            pipeline().fireChannelReadComplete();
        }
        finally {
            inRead = false;
        }
    }

    void peerInitiatedStream(QuicStream stream) {
        if (state == State.CLOSED) {
            stream.resetStream(0);
            return;
        }
        KwikQuicStreamChannel streamChannel = new KwikQuicStreamChannel(this, stream, false);
        streams.put(stream.getStreamId(), streamChannel);
        // Unhandled, it is set up with the stream handler and registered, see newChannelPipeline
        pipeline().fireChannelRead(streamChannel);
        pipeline().fireChannelReadComplete();
    }

    void streamClosed(KwikQuicStreamChannel streamChannel) {
        streams.remove((int) streamChannel.streamId());
    }

    private void connectionTerminated(ConnectionTerminatedEvent event) {
        // kwik calls an idle timeout with data still unacknowledged a lost connection; quiche counts both as timed out
        timedOut = event.closeReason() == ConnectionTerminatedEvent.CloseReason.IdleTimeout
                || event.closeReason() == ConnectionTerminatedEvent.CloseReason.ConnectionLost;
        QuicConnectionCloseEvent closeEvent = null;
        if (!closeEventFired) {
            closeEventFired = true;
            Long code = event.hasApplicationError()? event.applicationErrorCode(): event.transportErrorCode();
            closeEvent = new QuicConnectionCloseEvent(event.hasApplicationError(), code == null? 0: (int) (long) code,
                    new byte[0]);
            pipeline().fireUserEventTriggered(closeEvent);
        }
        ChannelPromise promise = connectPromise;
        if (promise != null) {
            connectPromise = null;
            QuicClosedChannelException cause = new QuicClosedChannelException(closeEvent);
            pipeline().fireUserEventTriggered(new SslHandshakeCompletionEvent(cause));
            promise.tryFailure(cause);
        }
        if (isOpen()) {
            unsafe().close(voidPromise());
        }
    }

    @Override
    protected DefaultChannelPipeline newChannelPipeline() {
        return new DefaultChannelPipeline(this) {
            @Override
            protected void onUnhandledInboundMessage(ChannelHandlerContext ctx, Object msg) {
                if (msg instanceof QuicStreamChannel) {
                    QuicStreamChannel channel = (QuicStreamChannel) msg;
                    Quic.setupChannel(channel, streamOptions, streamAttrs, streamHandler, LOGGER);
                    ctx.channel().eventLoop().register(channel);
                }
                else {
                    super.onUnhandledInboundMessage(ctx, msg);
                }
            }
        };
    }

    @Override
    public Future<QuicStreamChannel> createStream(QuicStreamType type, @Nullable ChannelHandler handler,
                                                  Promise<QuicStreamChannel> promise) {
        runOnLoop(() -> {
            if (!promise.setUncancellable()) {
                return;
            }
            if (connection == null || state != State.ACTIVE) {
                promise.setFailure(new ClosedChannelException());
                return;
            }
            QuicStream stream;
            try {
                stream = connection.tryCreateStream(type == QuicStreamType.BIDIRECTIONAL);
            }
            catch (Exception e) {
                promise.setFailure(e);
                return;
            }
            if (stream == null) {
                promise.setFailure(new QuicException("STREAM_LIMIT", QuicTransportError.STREAM_LIMIT_ERROR));
                return;
            }
            KwikQuicStreamChannel streamChannel = new KwikQuicStreamChannel(this, stream, true);
            streams.put(stream.getStreamId(), streamChannel);
            if (handler != null) {
                streamChannel.pipeline().addLast(handler);
            }
            eventLoop().register(streamChannel).addListener((ChannelFuture f) -> {
                if (f.isSuccess()) {
                    promise.setSuccess(streamChannel);
                }
                else {
                    streams.remove(stream.getStreamId());
                    promise.setFailure(f.cause());
                }
            });
        });
        return promise;
    }

    @Override
    public ChannelFuture close(boolean applicationClose, int error, ByteBuf reason, ChannelPromise promise) {
        String reasonText = reason.toString(StandardCharsets.UTF_8);
        reason.release();
        runOnLoop(() -> {
            QuicConnection conn = connection;
            if (conn != null && state != State.CLOSED) {
                if (applicationClose) {
                    conn.close(error, reasonText);
                }
                else {
                    conn.close();
                }
            }
            unsafe().close(promise);
        });
        return promise;
    }

    @Override
    public SSLEngine sslEngine() {
        return sslEngine;
    }

    @Override
    public long peerAllowedStreams(QuicStreamType type) {
        QuicConnection conn = connection;
        return conn == null || state != State.ACTIVE? 0: conn.availableStreams(type == QuicStreamType.BIDIRECTIONAL);
    }

    @Override
    public boolean isTimedOut() {
        return timedOut;
    }

    @Override
    @Nullable
    public QuicTransportParameters peerTransportParameters() {
        return null;
    }

    @Override
    public QuicConnectionAddress localAddress() {
        QuicConnection conn = connection;
        return conn == null? QuicConnectionAddress.EPHEMERAL: new QuicConnectionAddress(conn.localConnectionId());
    }

    @Override
    public QuicConnectionAddress remoteAddress() {
        QuicConnection conn = connection;
        return conn == null? QuicConnectionAddress.EPHEMERAL: new QuicConnectionAddress(conn.peerConnectionId());
    }

    @Override
    @Nullable
    public SocketAddress localSocketAddress() {
        SocketAddress local = localSocketAddress;
        return local != null? local: parent().localAddress();
    }

    @Override
    public SocketAddress remoteSocketAddress() {
        return remoteSocketAddress;
    }

    @Override
    public Future<QuicConnectionStats> collectStats(Promise<QuicConnectionStats> promise) {
        return promise.setFailure(new UnsupportedOperationException("not supported by the kwik based implementation"));
    }

    @Override
    public Future<QuicConnectionPathStats> collectPathStats(int pathIdx, Promise<QuicConnectionPathStats> promise) {
        return promise.setFailure(new UnsupportedOperationException("not supported by the kwik based implementation"));
    }

    @Override
    public QuicChannelConfig config() {
        return config;
    }

    @Override
    public boolean isOpen() {
        return state != State.CLOSED;
    }

    @Override
    public boolean isActive() {
        return state == State.ACTIVE;
    }

    @Override
    public ChannelMetadata metadata() {
        return METADATA;
    }

    @Override
    public QuicChannel read() {
        super.read();
        return this;
    }

    @Override
    public QuicChannel flush() {
        super.flush();
        return this;
    }

    @Override
    protected AbstractUnsafe newUnsafe() {
        return new QuicChannelUnsafe();
    }

    @Override
    protected boolean isCompatible(EventLoop loop) {
        // kwik runs the connection on the event loop of the UDP channel
        return loop == parent().eventLoop();
    }

    @Override
    protected SocketAddress localAddress0() {
        return localAddress();
    }

    @Override
    protected SocketAddress remoteAddress0() {
        return remoteAddress();
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
        if (state == State.CLOSED) {
            return;
        }
        state = State.CLOSED;
        QuicConnection conn = connection;
        if (conn != null) {
            // A no-op when kwik closed it already
            conn.close();
        }
        for (KwikQuicStreamChannel stream : new ArrayList<>(streams.values())) {
            stream.connectionClosed();
        }
        streams.clear();
        ChannelPromise promise = connectPromise;
        if (promise != null) {
            connectPromise = null;
            promise.tryFailure(new ClosedChannelException());
        }
    }

    @Override
    protected void doBeginRead() {
        // Streams are delivered as they arrive; reads only apply to datagrams
        readPending = true;
        readDatagrams();
    }

    @Override
    protected void doWrite(ChannelOutboundBuffer in) {
        for (;;) {
            Object msg = in.current();
            if (msg == null) {
                return;
            }
            QuicConnection conn = connection;
            if (conn == null || !conn.canSendDatagram()) {
                in.remove(new UnsupportedOperationException("QUIC datagrams are not enabled"));
                continue;
            }
            ByteBuf buf = (ByteBuf) msg;
            byte[] data = new byte[buf.readableBytes()];
            buf.getBytes(buf.readerIndex(), data);
            try {
                conn.sendDatagram(data);
                in.remove();
            }
            catch (RuntimeException e) {
                in.remove(e);
            }
        }
    }

    @Override
    protected Object filterOutboundMessage(Object msg) {
        if (msg instanceof ByteBuf) {
            return msg;
        }
        io.netty.util.ReferenceCountUtil.release(msg);
        throw new UnsupportedOperationException("unsupported message type: " + msg.getClass().getName());
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
     * Called by the codec, when the connect went through the UDP channel's pipeline, as with quiche.
     */
    void connectClient(KwikQuicClientCodec codec) throws Exception {
        KwikQuicSslContext ssl = quicConfig.sslContext;
        List<String> protocols = ssl.applicationProtocols();
        if (protocols.isEmpty()) {
            throw new IllegalStateException("QUIC needs an application protocol (ALPN)");
        }
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .host(remoteSocketAddress.getHostString())
                .port(remoteSocketAddress.getPort())
                // kwik offers one application protocol
                .applicationProtocol(protocols.get(0))
                .sharedEndpoint(codec.endpoint())
                .connectionExecutor(eventLoop())
                .logger(KwikLogging.logger());
        int connectTimeoutMillis = config.getConnectTimeoutMillis();
        if (connectTimeoutMillis > 0) {
            builder.connectTimeout(Duration.ofMillis(connectTimeoutMillis));
        }
        if (quicConfig.maxIdleTimeout != null) {
            builder.maxIdleTimeout(Duration.ofMillis(quicConfig.maxIdleTimeout));
        }
        if (quicConfig.initialMaxStreamDataBidiRemote != null) {
            builder.defaultStreamReceiveBufferSize(quicConfig.initialMaxStreamDataBidiRemote);
        }
        if (quicConfig.initialMaxStreamsBidi != null) {
            builder.maxOpenPeerInitiatedBidirectionalStreams((int) Long.min(quicConfig.initialMaxStreamsBidi, Integer.MAX_VALUE));
        }
        if (quicConfig.initialMaxStreamsUni != null) {
            builder.maxOpenPeerInitiatedUnidirectionalStreams((int) Long.min(quicConfig.initialMaxStreamsUni, Integer.MAX_VALUE));
        }
        X509TrustManager trustManager = ssl.trustManager();
        if (trustManager instanceof X509ExtendedTrustManager) {
            builder.customTrustManager(withEngine((X509ExtendedTrustManager) trustManager, sslEngine));
        }
        else if (trustManager != null) {
            builder.customTrustManager(trustManager);
        }
        // In Netty, checking the host name is the trust manager's job (through the SSLEngine's endpoint identification),
        // so with a custom trust manager (e.g. one accepting libp2p's self-signed certificates) kwik must not do it too
        if (trustManager != null || ssl.endpointIdentificationAlgorithm() == null) {
            builder.noHostnameVerification();
        }
        X509ExtendedKeyManager keyManager = ssl.keyManager();
        if (keyManager != null) {
            builder.clientKeyManager(keyManager);
        }
        if (quicConfig.datagramRecvQueueLen > 0) {
            builder.enableDatagramExtension();
        }
        QuicClientConnection client = builder.build();
        attach(client, protocols.get(0));
        client.connectAsync().whenComplete((ok, failure) -> runOnLoop(() -> {
            ChannelPromise pending = connectPromise;
            if (pending == null) {
                return;
            }
            connectPromise = null;
            if (failure == null && state == State.OPEN) {
                state = State.ACTIVE;
                sslEngine.handshakeFinished(client.getPeerCertificateChain(), applicationProtocol);
                if (pending.trySuccess()) {
                    fireDatagramExtensionEvent();
                    pipeline().fireChannelActive();
                    pipeline().fireUserEventTriggered(SslHandshakeCompletionEvent.SUCCESS);
                    pipeline().fireUserEventTriggered(QuicStreamLimitChangedEvent.INSTANCE);
                }
                else {
                    unsafe().close(voidPromise());
                }
            }
            else {
                connectPromise = pending;
                connectFailed(failure);
            }
        }));
    }

    private void connectFailed(@Nullable Throwable failure) {
        ChannelPromise pending = connectPromise;
        if (pending == null) {
            return;
        }
        connectPromise = null;
        Throwable cause = failure != null? failure: new ClosedChannelException();
        if (cause instanceof java.util.concurrent.CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (cause instanceof java.net.SocketTimeoutException) {
            cause = new ConnectTimeoutException("connection timed out: " + remoteSocketAddress);
        }
        else if (cause instanceof PeerClosedConnectionException) {
            PeerClosedConnectionException peerClose = (PeerClosedConnectionException) cause;
            QuicConnectionCloseEvent closeEvent = new QuicConnectionCloseEvent(peerClose.isApplicationError(),
                    (int) peerClose.errorCode(), peerClose.reason().getBytes(StandardCharsets.UTF_8));
            if (!closeEventFired) {
                closeEventFired = true;
                pipeline().fireUserEventTriggered(closeEvent);
            }
            cause = new QuicClosedChannelException(closeEvent).initCause(cause);
        }
        else if (cause instanceof java.net.ConnectException) {
            cause = new QuicClosedChannelException(null).initCause(cause);
        }
        pipeline().fireUserEventTriggered(new SslHandshakeCompletionEvent(cause));
        pending.tryFailure(cause);
        unsafe().close(voidPromise());
    }

    /**
     * kwik calls the plain {@link X509TrustManager} methods; an extended one gets the channel's engine, as with quiche.
     */
    private static X509TrustManager withEngine(X509ExtendedTrustManager tm, SSLEngine engine) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                tm.checkClientTrusted(chain, authType, engine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                tm.checkServerTrusted(chain, authType, engine);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return tm.getAcceptedIssuers();
            }
        };
    }

    private final class QuicChannelUnsafe extends AbstractUnsafe {
        @Override
        public void close(ChannelPromise promise) {
            QuicConnection conn = connection;
            if (conn == null || state == State.CLOSED || !eventLoop().inEventLoop()) {
                super.close(promise);
                return;
            }
            // kwik writes the CONNECTION_CLOSE to the parent now; completing the close in a later task lets those
            // writes go first, so a parent closed when this close completes still sends them
            conn.close();
            eventLoop().execute(() -> super.close(promise));
        }

        @Override
        public void connect(SocketAddress remote, @Nullable SocketAddress local, ChannelPromise promise) {
            assert eventLoop().inEventLoop();
            if (!promise.setUncancellable()) {
                return;
            }
            if (server) {
                promise.setFailure(new UnsupportedOperationException());
                return;
            }
            if (connectPromise != null) {
                promise.setFailure(new ConnectionPendingException());
                return;
            }
            if (connection != null) {
                promise.setFailure(new AlreadyConnectedException());
                return;
            }
            if (local instanceof QuicConnectionAddress) {
                requestedConnectionAddress = (QuicConnectionAddress) local;
            }
            connectPromise = promise;
            parent().connect(new KwikQuicChannelAddress(KwikQuicChannel.this)).addListener(f -> {
                if (!f.isSuccess() && connectPromise == promise) {
                    connectPromise = null;
                    promise.tryFailure(f.cause());
                    close(voidPromise());
                }
            });
            int connectTimeoutMillis = config.getConnectTimeoutMillis();
            if (connectTimeoutMillis > 0) {
                // kwik times out too; this only makes the exception the one Netty users expect
                eventLoop().schedule(() -> {
                    ChannelPromise pending = connectPromise;
                    if (pending != null && pending.tryFailure(new ConnectTimeoutException(
                            "connection timed out: " + remoteSocketAddress))) {
                        connectPromise = null;
                        close(voidPromise());
                    }
                }, connectTimeoutMillis, TimeUnit.MILLISECONDS);
            }
        }
    }
}
