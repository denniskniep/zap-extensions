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

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.logreader.handler.ApplicationLogMessageReceivedHandler;
import org.zaproxy.zap.extension.logreader.linker.ApplicationLogToHttpMessagesLinker;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ApplicationLogManager {
    private static final Logger LOGGER = Logger.getLogger(ApplicationLogManager.class);

    private static final String TIMESTAMP = "@timestamp";
    private static final String MESSAGE = "message";
    private static final String LEVEL = "level";

    private List<ApplicationLogMessageReceivedHandler> logReceivedHandlers;
    private List<ApplicationLogToHttpMessagesLinker> linkers;

    public ApplicationLogManager() {
        this.logReceivedHandlers = new ArrayList<>();
        this.linkers = new ArrayList<>();
    }

    public void add(Map<String, Object> logMessageProperties){
        ApplicationLogMessage logMessage = mapToObject(logMessageProperties);
        if(logMessage == null){
            LOGGER.warn("Map can not be parsed to application log. skipping log message");
            return;
        }

        List<HistoryIdLink> historyIdLinks = link(logMessage);
        LinkedApplicationLogMessage logToHttpMessage = new LinkedApplicationLogMessage(logMessage, historyIdLinks);
        handleLogReceived(logToHttpMessage);
    }

    private ApplicationLogMessage mapToObject(Map<String, Object> logMessageProperties) {
        String timeStamp = tryGetValue(logMessageProperties, TIMESTAMP);
        String message = tryGetValue(logMessageProperties, MESSAGE);
        String level = tryGetValue(logMessageProperties, LEVEL);
        if(timeStamp != null && message != null && level != null){
            return new ApplicationLogMessage(timeStamp, level, message, logMessageProperties);
        }
        return null;
    }

    private String tryGetValue(Map<String, Object> logMessageProperties, String key) {
        Object value = logMessageProperties.get(key);
        if(value == null){
            LOGGER.warn("Application log does not contain '"+key+"'");
            return null;
        }
        return value.toString();
    }

    private List<HistoryIdLink> link(ApplicationLogMessage logMessage){
        ArrayList<HistoryIdLink> historyIdLinks = new ArrayList<>();
        for (ApplicationLogToHttpMessagesLinker linker : linkers) {
            String linkerName = linker.getName();
            List<Integer> relatedHttpMessageHistoryIds = linker.findRelatedHttpMessageHistoryIds(logMessage);
            for (Integer historyId : relatedHttpMessageHistoryIds) {
                historyIdLinks.add(new HistoryIdLink(linkerName, historyId));
            }
        }
        return historyIdLinks;
    }

    private synchronized void handleLogReceived(LinkedApplicationLogMessage logToHttpMessage) {
        for (ApplicationLogMessageReceivedHandler logReceivedHandler : logReceivedHandlers) {
            logReceivedHandler.handleLogReceived(logToHttpMessage);
        }
    }

    public void registerHandler(ApplicationLogMessageReceivedHandler handler) {
        LOGGER.debug("Registering handler");
        logReceivedHandlers.add(handler);
    }

    public void removeHandler(ApplicationLogMessageReceivedHandler handler) {
        LOGGER.debug("Removing registered handler");
        logReceivedHandlers.remove(handler);
    }

    public void addLinker(ApplicationLogToHttpMessagesLinker linker) {
        linkers.add(linker);
    }
}
