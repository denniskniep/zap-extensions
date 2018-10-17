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

import java.util.Collections;
import java.util.Map;

/**
 * Represents a LogMessage from the tested Application
 */
public class ApplicationLogMessage {
    private String timestamp;
    private String level;
    private String message;
    private Map<String, Object> properties;

    public ApplicationLogMessage(String timestamp, String level, String message, Map<String, Object> properties) {
        this.timestamp = timestamp;
        this.level = level;
        this.message = message;
        this.properties = properties;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getLevel() {
        return level;
    }

    public String getMessage() {
        return message;
    }

    public Map<String, Object> getProperties() {
        return Collections.unmodifiableMap(properties);
    }

}
