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
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.ssl.ClientAuth;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.GlobalEventExecutor;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.jetbrains.annotations.Nullable;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.core.server.impl.ServerConnectionImpl;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * The server codec: a kwik {@link ServerConnector} that sends through, and receives from, the UDP channel this handler is
 * in, and runs its connections on that channel's event loop. Each connection whose handshake finishes becomes a
 * {@link KwikQuicChannel}.
 */
final class KwikQuicServerCodec extends ChannelDuplexHandler {

    private static final InternalLogger LOGGER = InternalLoggerFactory.getInstance(KwikQuicServerCodec.class);
    private static final char[] KEY_PASSWORD = new char[0];

    private final KwikConfig config;
    private final int localConnIdLength;
    private final QuicTokenHandler tokenHandler;
    @Nullable private final ChannelHandler handler;
    private final Map.Entry<ChannelOption<?>, Object>[] options;
    private final Map.Entry<AttributeKey<?>, Object>[] attrs;
    @Nullable private final ChannelHandler streamHandler;
    private final Map.Entry<ChannelOption<?>, Object>[] streamOptions;
    private final Map.Entry<AttributeKey<?>, Object>[] streamAttrs;
    @Nullable private ServerConnector server;

    KwikQuicServerCodec(KwikConfig config, int localConnIdLength, QuicTokenHandler tokenHandler,
                        @Nullable ChannelHandler handler, Map.Entry<ChannelOption<?>, Object>[] options,
                        Map.Entry<AttributeKey<?>, Object>[] attrs, @Nullable ChannelHandler streamHandler,
                        Map.Entry<ChannelOption<?>, Object>[] streamOptions,
                        Map.Entry<AttributeKey<?>, Object>[] streamAttrs) {
        this.config = config;
        this.localConnIdLength = localConnIdLength;
        this.tokenHandler = tokenHandler;
        this.handler = handler;
        this.options = options;
        this.attrs = attrs;
        this.streamHandler = streamHandler;
        this.streamOptions = streamOptions;
        this.streamAttrs = streamAttrs;
    }

    @Override
    public boolean isSharable() {
        return false;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        KwikQuicSslContext ssl = config.sslContext;
        X509ExtendedKeyManager keyManager = ssl.keyManager();
        if (keyManager == null) {
            throw new IllegalStateException("a QUIC server needs a key manager");
        }
        String alias = serverAlias(keyManager);
        PrivateKey key = keyManager.getPrivateKey(alias);
        X509Certificate[] chain = keyManager.getCertificateChain(alias);
        // kwik takes the server's key and certificate as a key store
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", key, KEY_PASSWORD, chain);

        ServerConnectionConfig.Builder connectionConfig = ServerConnectionConfig.builder()
                .connectionIdLength(localConnIdLength == 0? 8: Integer.max(4, localConnIdLength))
                // Netty's handlers that do address validation (e.g. InsecureQuicTokenHandler) use retry
                .retryRequired(!(tokenHandler instanceof NoQuicTokenHandler));
        if (config.maxIdleTimeout != null) {
            connectionConfig.maxIdleTimeout((int) Long.min(config.maxIdleTimeout, Integer.MAX_VALUE));
        }
        if (config.initialMaxData != null) {
            connectionConfig.maxConnectionBufferSize(config.initialMaxData);
        }
        if (config.initialMaxStreamDataBidiRemote != null) {
            connectionConfig.maxBidirectionalStreamBufferSize(config.initialMaxStreamDataBidiRemote);
        }
        if (config.initialMaxStreamDataUni != null) {
            connectionConfig.maxUnidirectionalStreamBufferSize(config.initialMaxStreamDataUni);
        }
        int maxBidi = config.initialMaxStreamsBidi != null? (int) Long.min(config.initialMaxStreamsBidi, Integer.MAX_VALUE): 100;
        int maxUni = config.initialMaxStreamsUni != null? (int) Long.min(config.initialMaxStreamsUni, Integer.MAX_VALUE): 0;
        connectionConfig.maxOpenPeerInitiatedBidirectionalStreams(maxBidi);
        connectionConfig.maxOpenPeerInitiatedUnidirectionalStreams(maxUni);

        ServerConnector.Builder builder = ServerConnector.builder()
                .withDatagramSender(new KwikDatagramSender(ctx))
                .withConnectionExecutor(ctx.channel().eventLoop())
                .withKeyStore(keyStore, "server", KEY_PASSWORD)
                .withConfiguration(connectionConfig.build())
                .withLogger(KwikLogging.logger());
        if (ssl.clientAuth() == ClientAuth.REQUIRE) {
            X509TrustManager trustManager = ssl.trustManager();
            if (trustManager == null) {
                throw new IllegalStateException("client authentication needs a trust manager");
            }
            builder.requireClientCertificate(trustManager);
        }
        else if (ssl.clientAuth() == ClientAuth.OPTIONAL) {
            LOGGER.warn("ClientAuth.OPTIONAL is not supported by the kwik based implementation; not requesting client certificates");
        }
        ServerConnector connector = builder.build();
        for (String protocol : ssl.applicationProtocols()) {
            connector.registerApplicationProtocol(protocol, new ConnectionFactory(ctx, maxBidi, maxUni));
        }
        connector.start();
        server = connector;
    }

    private static String serverAlias(X509ExtendedKeyManager keyManager) {
        for (String keyType : new String[] { "EC", "RSA", "Ed25519", "EdDSA" }) {
            String[] aliases = keyManager.getServerAliases(keyType, null);
            if (aliases != null && aliases.length > 0) {
                return aliases[0];
            }
        }
        throw new IllegalStateException("no server key in the key manager");
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DatagramPacket && server != null) {
            DatagramPacket packet = (DatagramPacket) msg;
            try {
                server.receive(packet.content().nioBuffer(), packet.sender());
            }
            finally {
                packet.release();
            }
        }
        else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        closeServer();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        closeServer();
        ctx.fireChannelInactive();
    }

    private void closeServer() {
        ServerConnector connector = server;
        if (connector != null) {
            server = null;
            // close() waits for the connections to close, which run on the event loop, so it must not run there
            GlobalEventExecutor.INSTANCE.execute(connector::close);
        }
    }

    private final class ConnectionFactory implements ApplicationProtocolConnectionFactory {
        private final ChannelHandlerContext ctx;
        private final int maxBidi;
        private final int maxUni;

        ConnectionFactory(ChannelHandlerContext ctx, int maxBidi, int maxUni) {
            this.ctx = ctx;
            this.maxBidi = maxBidi;
            this.maxUni = maxUni;
        }

        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection connection) {
            InetSocketAddress remote = connection instanceof ServerConnectionImpl?
                    ((ServerConnectionImpl) connection).getInitialRemoteAddress(): new InetSocketAddress(0);
            KwikQuicChannel channel = KwikQuicChannel.forServer(ctx.channel(), config, connection, protocol, remote,
                    streamHandler, streamOptions, streamAttrs);
            Quic.setupChannel(channel, options, attrs, handler, LOGGER);
            ctx.channel().eventLoop().register(channel).addListener(f -> {
                if (f.isSuccess()) {
                    channel.handshakeCompleted();
                }
                else {
                    connection.close();
                }
            });
            return new ApplicationProtocolConnection() {
                @Override
                public void acceptPeerInitiatedStream(QuicStream stream) {
                    channel.peerInitiatedStream(stream);
                }
            };
        }

        @Override
        public boolean enableDatagramExtension() {
            return config.datagramRecvQueueLen > 0;
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return maxBidi;
        }

        @Override
        public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
            return maxUni;
        }
    }
}
