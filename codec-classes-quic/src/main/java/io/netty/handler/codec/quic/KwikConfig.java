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

import org.jetbrains.annotations.Nullable;

import java.util.function.Function;

/**
 * The settings of a {@link QuicCodecBuilder}, for the kwik based codecs. Settings that kwik has no equivalent for
 * (grease, hystart, pmtu discovery, the congestion control algorithm and its initial window, the datagram send queue) are accepted
 * by the builder but not used.
 */
final class KwikConfig {

    final int version;
    @Nullable final Long maxIdleTimeout;
    @Nullable final Long maxSendUdpPayloadSize;
    @Nullable final Long maxRecvUdpPayloadSize;
    @Nullable final Long initialMaxData;
    @Nullable final Long initialMaxStreamDataBidiLocal;
    @Nullable final Long initialMaxStreamDataBidiRemote;
    @Nullable final Long initialMaxStreamDataUni;
    @Nullable final Long initialMaxStreamsBidi;
    @Nullable final Long initialMaxStreamsUni;
    @Nullable final Long ackDelayExponent;
    @Nullable final Long maxAckDelay;
    @Nullable final Boolean disableActiveMigration;
    @Nullable final Long activeConnectionIdLimit;
    @Nullable final byte[] statelessResetToken;
    final KwikQuicSslContext sslContext;
    final Function<QuicChannel, ? extends QuicSslEngine> sslEngineProvider;
    // 0 when datagrams (RFC 9221) are disabled
    final int datagramRecvQueueLen;

    KwikConfig(int version, @Nullable Long maxIdleTimeout, @Nullable Long maxSendUdpPayloadSize,
               @Nullable Long maxRecvUdpPayloadSize, @Nullable Long initialMaxData,
               @Nullable Long initialMaxStreamDataBidiLocal, @Nullable Long initialMaxStreamDataBidiRemote,
               @Nullable Long initialMaxStreamDataUni, @Nullable Long initialMaxStreamsBidi,
               @Nullable Long initialMaxStreamsUni, @Nullable Long ackDelayExponent, @Nullable Long maxAckDelay,
               @Nullable Boolean disableActiveMigration, @Nullable Long activeConnectionIdLimit,
               @Nullable byte[] statelessResetToken, KwikQuicSslContext sslContext,
               Function<QuicChannel, ? extends QuicSslEngine> sslEngineProvider, int datagramRecvQueueLen) {
        this.version = version;
        this.maxIdleTimeout = maxIdleTimeout;
        this.maxSendUdpPayloadSize = maxSendUdpPayloadSize;
        this.maxRecvUdpPayloadSize = maxRecvUdpPayloadSize;
        this.initialMaxData = initialMaxData;
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
        this.initialMaxStreamDataUni = initialMaxStreamDataUni;
        this.initialMaxStreamsBidi = initialMaxStreamsBidi;
        this.initialMaxStreamsUni = initialMaxStreamsUni;
        this.ackDelayExponent = ackDelayExponent;
        this.maxAckDelay = maxAckDelay;
        this.disableActiveMigration = disableActiveMigration;
        this.activeConnectionIdLimit = activeConnectionIdLimit;
        this.statelessResetToken = statelessResetToken;
        this.sslContext = sslContext;
        this.sslEngineProvider = sslEngineProvider;
        this.datagramRecvQueueLen = datagramRecvQueueLen;
    }
}
