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

import io.netty.util.internal.EmptyArrays;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The {@link QuicSslEngine} of a kwik based channel. kwik (agent15) does the TLS, so this engine does not wrap or unwrap
 * anything: it reports what the handshake established, i.e. the peer's certificates and the negotiated application
 * protocol, through {@link #getSession()} and {@link #getApplicationProtocol()}.
 */
final class KwikQuicSslEngine extends QuicSslEngine {

    private final KwikQuicSslContext context;
    private final boolean client;
    @Nullable private final String peerHost;
    private final int peerPort;
    private volatile Certificate @Nullable [] peerCertificates;
    private volatile Certificate @Nullable [] localCertificates;
    @Nullable private volatile String applicationProtocol;
    private volatile boolean handshakeDone;
    private final long creationTime = System.currentTimeMillis();
    private final SSLSession session = new KwikSession();

    KwikQuicSslEngine(KwikQuicSslContext context, boolean client, @Nullable String peerHost, int peerPort) {
        this.context = context;
        this.client = client;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    KwikQuicSslContext context() {
        return context;
    }

    /**
     * Called by the channel when the handshake has finished.
     */
    void handshakeFinished(@Nullable List<X509Certificate> peerChain, @Nullable String applicationProtocol) {
        this.peerCertificates = peerChain == null || peerChain.isEmpty()? null: peerChain.toArray(new Certificate[0]);
        this.applicationProtocol = applicationProtocol;
        this.handshakeDone = true;
    }

    void localCertificates(@Nullable List<X509Certificate> chain) {
        this.localCertificates = chain == null || chain.isEmpty()? null: chain.toArray(new Certificate[0]);
    }

    @Override
    @Nullable
    public String getApplicationProtocol() {
        return applicationProtocol;
    }

    @Override
    @Nullable
    public String getHandshakeApplicationProtocol() {
        return applicationProtocol;
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    @Nullable
    public SSLParameters getSSLParameters() {
        SSLParameters parameters = super.getSSLParameters();
        // Read by X509ExtendedTrustManagers to check the host name
        parameters.setEndpointIdentificationAlgorithm(context.endpointIdentificationAlgorithm());
        return parameters;
    }

    @Override
    public SSLSession getHandshakeSession() {
        return handshakeDone? null: session;
    }

    @Override
    @Nullable
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        throw new UnsupportedOperationException();
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
        throw new UnsupportedOperationException();
    }

    @Override
    @Nullable
    public Runnable getDelegatedTask() {
        return null;
    }

    @Override
    public void closeInbound() {
    }

    @Override
    public boolean isInboundDone() {
        return false;
    }

    @Override
    public void closeOutbound() {
    }

    @Override
    public boolean isOutboundDone() {
        return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return new String[] { "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256" };
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return getSupportedCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[] { "TLSv1.3" };
    }

    @Override
    public String[] getEnabledProtocols() {
        return getSupportedProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void beginHandshake() {
        throw new UnsupportedOperationException();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    @Override
    public void setUseClientMode(boolean clientMode) {
        if (clientMode != client) {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public boolean getUseClientMode() {
        return client;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }

    private final class KwikSession implements SSLSession {

        @Override
        public byte[] getId() {
            return EmptyArrays.EMPTY_BYTES;
        }

        @Override
        @Nullable
        public SSLSessionContext getSessionContext() {
            return null;
        }

        @Override
        public long getCreationTime() {
            return creationTime;
        }

        @Override
        public long getLastAccessedTime() {
            return creationTime;
        }

        @Override
        public void invalidate() {
        }

        @Override
        public boolean isValid() {
            return handshakeDone;
        }

        @Override
        public void putValue(String name, Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        @Nullable
        public Object getValue(String name) {
            return null;
        }

        @Override
        public void removeValue(String name) {
        }

        @Override
        public String[] getValueNames() {
            return EmptyArrays.EMPTY_STRINGS;
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            Certificate[] certificates = peerCertificates;
            if (certificates == null) {
                throw new SSLPeerUnverifiedException("peer not verified");
            }
            return certificates.clone();
        }

        @Override
        public Certificate @Nullable [] getLocalCertificates() {
            Certificate[] certificates = localCertificates;
            return certificates == null? null: certificates.clone();
        }

        @Override
        @SuppressWarnings("deprecation")
        public javax.security.cert.X509Certificate[] getPeerCertificateChain() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            return ((X509Certificate) getPeerCertificates()[0]).getSubjectX500Principal();
        }

        @Override
        @Nullable
        public Principal getLocalPrincipal() {
            Certificate[] certificates = localCertificates;
            return certificates == null? null: ((X509Certificate) certificates[0]).getSubjectX500Principal();
        }

        @Override
        public String getCipherSuite() {
            return "TLS_AES_128_GCM_SHA256";
        }

        @Override
        public String getProtocol() {
            return "TLSv1.3";
        }

        @Override
        @Nullable
        public String getPeerHost() {
            return peerHost;
        }

        @Override
        public int getPeerPort() {
            return peerPort;
        }

        @Override
        public int getPacketBufferSize() {
            return Quic.MAX_DATAGRAM_SIZE;
        }

        @Override
        public int getApplicationBufferSize() {
            return Quic.MAX_DATAGRAM_SIZE;
        }
    }
}
