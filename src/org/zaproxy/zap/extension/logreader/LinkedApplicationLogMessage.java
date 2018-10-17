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
import java.util.List;
import java.util.stream.Collectors;

public class LinkedApplicationLogMessage {
    private ApplicationLogMessage logMessage;
    private List<HistoryIdLink> historyIdLinks;

    public LinkedApplicationLogMessage(ApplicationLogMessage logMessage, List<HistoryIdLink> historyIdLinks) {
       if(logMessage == null) throw new IllegalArgumentException("logMessage is null");
       if(historyIdLinks == null) throw new IllegalArgumentException("historyIdLinks is null");
        this.logMessage = logMessage;
        this.historyIdLinks = historyIdLinks;
    }

    public ApplicationLogMessage getLogMessage() {
        return logMessage;
    }

    public List<HistoryIdLink> getHistoryIdLinks() {
        return Collections.unmodifiableList(historyIdLinks);
    }

    public List<Integer> getHistoryIds() {
        return historyIdLinks.stream().map(i -> i.getHttpMessageHistoryId()).collect(Collectors.toList());
    }
}
