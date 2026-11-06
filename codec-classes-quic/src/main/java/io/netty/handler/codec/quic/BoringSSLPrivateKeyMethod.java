/*
 * Copyright 2019 The Netty Project
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

import java.util.function.BiConsumer;

/**
 * Allows to customize private key signing / decrypt (when using RSA).
 */
// The TLS SignatureScheme code points, as BoringSSL uses for SSL_SIGN_* (0xff01 is BoringSSL's own)
interface BoringSSLPrivateKeyMethod {
    int SSL_SIGN_RSA_PKCS1_SHA1 = 0x0201;
    int SSL_SIGN_RSA_PKCS1_SHA256 = 0x0401;
    int SSL_SIGN_RSA_PKCS1_SHA384 = 0x0501;
    int SSL_SIGN_RSA_PKCS1_SHA512 = 0x0601;
    int SSL_SIGN_ECDSA_SHA1 = 0x0203;
    int SSL_SIGN_ECDSA_SECP256R1_SHA256 =
            0x0403;
    int SSL_SIGN_ECDSA_SECP384R1_SHA384 =
            0x0503;
    int SSL_SIGN_ECDSA_SECP521R1_SHA512 =
            0x0603;
    int SSL_SIGN_RSA_PSS_RSAE_SHA256 = 0x0804;
    int SSL_SIGN_RSA_PSS_RSAE_SHA384 = 0x0805;
    int SSL_SIGN_RSA_PSS_RSAE_SHA512 = 0x0806;
    int SSL_SIGN_ED25519 = 0x0807;
    int SSL_SIGN_RSA_PKCS1_MD5_SHA1 = 0xff01;

    /**
     * Sign the input with given EC key and returns the signed bytes.
     *
     * @param ssl the SSL instance
     * @param signatureAlgorithm the algorithm to use for signing
     * @param input the input itself
     * @param callback the callback provides the signed bytes and an error if such occurs while signing
     */
    void sign(long ssl, int signatureAlgorithm, byte[] input, BiConsumer<byte[], Throwable> callback);

    /**
     * Decrypts the input with the given RSA key and returns the decrypted bytes.
     *
     * @param ssl the SSL instance
     * @param input the input which should be decrypted
     * @param callback the callback provides the decrypted bytes and an error if such occurs while decrypting
     */
    void decrypt(long ssl, byte[] input, BiConsumer<byte[], Throwable> callback);
}
