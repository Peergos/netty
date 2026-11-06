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

import io.netty.util.internal.SystemPropertyUtil;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.log.SysOutLogger;

/**
 * kwik's own logging, off unless system property {@code io.netty.quic.kwik.log} is {@code true}; for diagnosing.
 */
final class KwikLogging {

    private static final boolean ENABLED = SystemPropertyUtil.getBoolean("io.netty.quic.kwik.log", false);

    private KwikLogging() {
    }

    static Logger logger() {
        if (!ENABLED) {
            return new NullLogger();
        }
        SysOutLogger log = new SysOutLogger();
        log.logWarning(true);
        log.logInfo(true);
        return log;
    }
}
