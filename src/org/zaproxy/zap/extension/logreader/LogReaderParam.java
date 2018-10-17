/*
 *  Zed Attack Proxy (ZAP) and its related class files.
 *
 *  ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 *  Copyright 2018 The ZAP Development Team
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.zaproxy.zap.extension.logreader;

import org.parosproxy.paros.common.AbstractParam;

public class LogReaderParam extends AbstractParam {

    private static final String PROXY_BASE_KEY = "logreader";

    private static final String LOCAL_ADDRESS_KEY = PROXY_BASE_KEY + ".localaddr";
    private static final String PORT_KEY = PROXY_BASE_KEY + ".port";

    private static final String SECURE_KEY = PROXY_BASE_KEY + ".secure";

    private static final String LOG_DATE_TIME_FORMATTER_PATTERN_KEY = PROXY_BASE_KEY + ".logdatetimeformatterpattern";

    private static final String LOG_DATE_TIME_FORMATTER_ZONE_KEY = PROXY_BASE_KEY + ".logdatetimeformatterzone";

    private static final String LOG_DATE_TIME_TOLERANCE_IN_MS_KEY = PROXY_BASE_KEY + ".logdatetimetoleranceinms";

    private static final String LOG_DATE_TIME_OFFSET_IN_MS_KEY = PROXY_BASE_KEY + ".logdatetimeoffsetinms";

    public static final int DEFAULT_LOG_DATE_TIME_TOLERANCE_IN_MS = 100;
    public static final int DEFAULT_LOG_DATE_TIME_OFFSET_IN_MS = 0;
    public static final String DEFAULT_LOG_DATE_TIME_FORMATTER_PATTERN = "ISO_DATE_TIME";
    private static final int DEFAULT_PORT = 8915;
    public static final String DEFAULT_IP = "0.0.0.0";

    private String localAddress;
    private int port;
    private boolean secure;
    private String logDateTimeFormatterPattern;
    private int logDateTimeToleranceInMs;
    private int logDateTimeOffsetInMs;
    private String logDateTimeFormatterZone;

    public LogReaderParam() {
    }

    @Override
    protected void parse() {
        localAddress = getString(LOCAL_ADDRESS_KEY, DEFAULT_IP);
        port = getInt(PORT_KEY, DEFAULT_PORT);
        secure = getBoolean(SECURE_KEY, false);
        logDateTimeFormatterPattern = getString(LOG_DATE_TIME_FORMATTER_PATTERN_KEY, DEFAULT_LOG_DATE_TIME_FORMATTER_PATTERN);
        logDateTimeFormatterZone = getString(LOG_DATE_TIME_FORMATTER_ZONE_KEY, "");
        logDateTimeToleranceInMs = getInt(LOG_DATE_TIME_TOLERANCE_IN_MS_KEY, DEFAULT_LOG_DATE_TIME_TOLERANCE_IN_MS);
        logDateTimeOffsetInMs = getInt(LOG_DATE_TIME_OFFSET_IN_MS_KEY, DEFAULT_LOG_DATE_TIME_OFFSET_IN_MS);
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(String localAddress) {
        if (this.localAddress.equals(localAddress)) {
            return;
        }
        this.localAddress = localAddress.trim();
        getConfig().setProperty(LOCAL_ADDRESS_KEY, this.localAddress);
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        if (this.port == port) {
            return;
        }
        this.port = port;
        getConfig().setProperty(PORT_KEY, Integer.toString(this.port));
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        if (this.secure == secure) {
            return;
        }
        this.secure = secure;
        getConfig().setProperty(SECURE_KEY, Boolean.toString(this.secure));
    }

    public String getLogDateTimeFormatterPattern() {
        return logDateTimeFormatterPattern;
    }

    public void setLogDateTimeFormatterPattern(String logDateTimeFormatterPattern) {
        if (this.logDateTimeFormatterPattern == logDateTimeFormatterPattern) {
            return;
        }
        this.logDateTimeFormatterPattern = logDateTimeFormatterPattern;
        getConfig().setProperty(LOG_DATE_TIME_FORMATTER_PATTERN_KEY, this.logDateTimeFormatterPattern);
    }

    public int getLogDateTimeToleranceInMs() {
        return logDateTimeToleranceInMs;
    }

    public void setLogDateTimeToleranceInMs(int logDateTimeToleranceInMs) {
        if (this.logDateTimeToleranceInMs == logDateTimeToleranceInMs) {
            return;
        }
        this.logDateTimeToleranceInMs = logDateTimeToleranceInMs;
        getConfig().setProperty(LOG_DATE_TIME_TOLERANCE_IN_MS_KEY, Integer.toString(this.logDateTimeToleranceInMs));
    }

    public int getLogDateTimeOffsetInMs() {
        return logDateTimeOffsetInMs;
    }

    public void setLogDateTimeOffsetInMs(int logDateTimeOffsetInMs) {
        if (this.logDateTimeOffsetInMs == logDateTimeOffsetInMs) {
            return;
        }
        this.logDateTimeOffsetInMs = logDateTimeOffsetInMs;
        getConfig().setProperty(LOG_DATE_TIME_OFFSET_IN_MS_KEY, Integer.toString(this.logDateTimeOffsetInMs));
    }

    public String getLogDateTimeFormatterZone() {
        return logDateTimeFormatterZone;
    }

    public void setLogDateTimeFormatterZone(String logDateTimeFormatterZone) {
        if (this.logDateTimeFormatterZone == logDateTimeFormatterZone) {
            return;
        }
        this.logDateTimeFormatterZone = logDateTimeFormatterZone;
        getConfig().setProperty(LOG_DATE_TIME_FORMATTER_ZONE_KEY, this.logDateTimeFormatterZone);
    }
}
