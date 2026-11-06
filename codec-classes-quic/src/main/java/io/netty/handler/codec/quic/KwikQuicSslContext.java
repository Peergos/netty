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

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslHandler;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * The TLS settings for the kwik based codecs, which apply them when building their kwik endpoint: kwik and agent15 do
 * the TLS, so the engines this context creates only report what the handshake established (see
 * {@link KwikQuicSslEngine}).
 */
final class KwikQuicSslContext extends QuicSslContext {

    static final String DEFAULT_ENDPOINT_IDENTIFICATION_ALGORITHM = "HTTPS";

    private final boolean server;
    @Nullable private final KeyManagerFactory keyManagerFactory;
    @Nullable private final TrustManagerFactory trustManagerFactory;
    private final ClientAuth clientAuth;
    private final List<String> applicationProtocols;
    @Nullable private final String endpointIdentificationAlgorithm;
    private volatile long sessionCacheSize;
    private volatile long sessionTimeout;

    KwikQuicSslContext(boolean server, @Nullable KeyManagerFactory keyManagerFactory,
                       @Nullable TrustManagerFactory trustManagerFactory, ClientAuth clientAuth,
                       String @Nullable [] applicationProtocols, @Nullable String endpointIdentificationAlgorithm,
                       long sessionCacheSize, long sessionTimeout) {
        if (server && keyManagerFactory == null) {
            throw new IllegalArgumentException("a server needs a key manager");
        }
        this.server = server;
        this.keyManagerFactory = keyManagerFactory;
        this.trustManagerFactory = trustManagerFactory;
        this.clientAuth = clientAuth;
        this.applicationProtocols = applicationProtocols == null?
                Collections.emptyList(): Collections.unmodifiableList(Arrays.asList(applicationProtocols.clone()));
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
        this.sessionCacheSize = sessionCacheSize;
        this.sessionTimeout = sessionTimeout;
    }

    @Nullable
    X509ExtendedKeyManager keyManager() {
        if (keyManagerFactory == null) {
            return null;
        }
        for (KeyManager manager : keyManagerFactory.getKeyManagers()) {
            if (manager instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) manager;
            }
        }
        throw new IllegalArgumentException("No X509ExtendedKeyManager included");
    }

    @Nullable
    X509TrustManager trustManager() {
        if (trustManagerFactory == null) {
            return null;
        }
        for (TrustManager manager : trustManagerFactory.getTrustManagers()) {
            if (manager instanceof X509TrustManager) {
                return (X509TrustManager) manager;
            }
        }
        throw new IllegalArgumentException("No X509TrustManager included");
    }

    ClientAuth clientAuth() {
        return clientAuth;
    }

    List<String> applicationProtocols() {
        return applicationProtocols;
    }

    @Nullable
    String endpointIdentificationAlgorithm() {
        return endpointIdentificationAlgorithm;
    }

    @Override
    public boolean isClient() {
        return !server;
    }

    @Override
    public List<String> cipherSuites() {
        return Arrays.asList("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");
    }

    @Override
    public long sessionCacheSize() {
        return sessionCacheSize;
    }

    @Override
    public long sessionTimeout() {
        return sessionTimeout;
    }

    @Override
    public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
        return () -> applicationProtocols;
    }

    @Override
    public QuicSslEngine newEngine(ByteBufAllocator alloc) {
        return new KwikQuicSslEngine(this, isClient(), null, -1);
    }

    @Override
    public QuicSslEngine newEngine(ByteBufAllocator alloc, String peerHost, int peerPort) {
        return new KwikQuicSslEngine(this, isClient(), peerHost, peerPort);
    }

    @Override
    public QuicSslSessionContext sessionContext() {
        return new QuicSslSessionContext() {
            @Override
            public void setTicketKeys(SslSessionTicketKey @Nullable ... keys) {
                // kwik (agent15) manages session tickets itself
            }

            @Override
            @Nullable
            public SSLSession getSession(byte[] sessionId) {
                return null;
            }

            @Override
            public Enumeration<byte[]> getIds() {
                return Collections.emptyEnumeration();
            }

            @Override
            public void setSessionTimeout(int seconds) {
                sessionTimeout = seconds;
            }

            @Override
            public int getSessionTimeout() {
                return (int) sessionTimeout;
            }

            @Override
            public void setSessionCacheSize(int size) {
                sessionCacheSize = size;
            }

            @Override
            public int getSessionCacheSize() {
                return (int) sessionCacheSize;
            }
        };
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, boolean startTls) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SslHandler newHandler(ByteBufAllocator alloc, Executor delegatedTaskExecutor) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, boolean startTls, Executor executor) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, String peerHost, int peerPort, boolean startTls) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SslHandler newHandler(ByteBufAllocator alloc, String peerHost, int peerPort,
                                 Executor delegatedTaskExecutor) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SslHandler newHandler(ByteBufAllocator alloc, String peerHost, int peerPort,
                                    boolean startTls, Executor delegatedTaskExecutor) {
        throw new UnsupportedOperationException();
    }

    static X509Certificate @Nullable [] toX509Certificates0(@Nullable File file) throws CertificateException {
        return toX509Certificates(file);
    }

    static PrivateKey toPrivateKey0(@Nullable File keyFile, @Nullable String keyPassword) throws Exception {
        return toPrivateKey(keyFile, keyPassword);
    }

    static TrustManagerFactory buildTrustManagerFactory0(X509Certificate @Nullable [] certCollection) throws Exception {
        return buildTrustManagerFactory(certCollection, null, null);
    }
}
