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

package org.zaproxy.zap.extension.logreader.linker;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.logreader.ApplicationLogMessage;
import org.zaproxy.zap.extension.logreader.DateTimeParser;
import org.zaproxy.zap.extension.logreader.LogReaderParam;
import org.zaproxy.zap.extension.logreader.ui.options.OptionsLogReaderPanel;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;


/**
 * This class should be Thread-Safe due to it is used inside the following different Threads:
 * - Many Threads from LogReaderProxyListener
 */
public class TimebasedLinker implements ApplicationLogToHttpMessagesLinker {

    private static final String NAME = Constant.messages.getString("logreader.linker.timebased.name");
    private static final Logger LOGGER = Logger.getLogger(TimebasedLinker.class);
    private static final long MS_TO_NANOS_FACTOR = 1000000;

    private Model model;
    private DateTimeRangeList<Integer> historyIdCache;
    private Integer lastHistoryId;
    private String dateTimeFormatterPattern;
    private String dateTimeFormatterZone;
    private Integer dateTimeToleranceInMs;
    private Integer dateTimeOffsetInMs;


    public TimebasedLinker() {
        this.historyIdCache = new DateTimeRangeList<>();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public List<Integer> findRelatedHttpMessageHistoryIds(ApplicationLogMessage logMessage) {
        if(model == null) throw new NullPointerException("model is null");
        if(dateTimeFormatterPattern == null) throw new NullPointerException("dateTimeFormatterPattern is null");
        if(dateTimeFormatterZone == null) throw new NullPointerException("dateTimeFormatterZone is null");
        if(dateTimeToleranceInMs == null) throw new NullPointerException("dateTimeToleranceInMs is null");
        if(dateTimeOffsetInMs == null) throw new NullPointerException("dateTimeOffsetInMs is null");

        LocalDateTime logDateTime = parseTimestamp(logMessage.getTimestamp());
        if(logDateTime == null){
            return new ArrayList<>();
        }

        LocalDateTime from = logDateTime
                .plusNanos(dateTimeOffsetInMs * MS_TO_NANOS_FACTOR)
                .minusNanos(dateTimeToleranceInMs * MS_TO_NANOS_FACTOR);

        LocalDateTime till = logDateTime
                .plusNanos(dateTimeOffsetInMs * MS_TO_NANOS_FACTOR)
                .plusNanos(dateTimeToleranceInMs * MS_TO_NANOS_FACTOR);

        synchronized(this) {
            maintainHistoryIdCache();
            return historyIdCache.getIntersectingRangeValues(from, till);
        }
    }

    private LocalDateTime parseTimestamp(String timestamp) {
        try {
            return DateTimeParser.parseToUtc(timestamp, dateTimeFormatterPattern, dateTimeFormatterZone);
        }
        catch (DateTimeParseException e) {
            LOGGER.error("'"+timestamp+"' is not parsable with pattern '" + dateTimeFormatterPattern + "' !%n", e);
        }
        return null;
    }

    private void maintainHistoryIdCache() {
        int startAtHistoryId = lastHistoryId == null ? 0 : lastHistoryId + 1;
        for (RecordHistory historyRecord : getHistoryRecords(startAtHistoryId)) {
            Integer historyId = historyRecord.getHistoryId();
            long timeSentMillis = historyRecord.getHttpMessage().getTimeSentMillis();
            long timeReceivedMillis = timeSentMillis + historyRecord.getHttpMessage().getTimeElapsedMillis();
            LocalDateTime sentDateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(timeSentMillis), ZoneOffset.UTC);
            LocalDateTime receivedDateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(timeReceivedMillis), ZoneOffset.UTC);
            historyIdCache.add(sentDateTime, receivedDateTime, historyId);
            lastHistoryId = historyId;
        }
    }

    private List<RecordHistory> getHistoryRecords(int startAtHistoryId) {
        List<RecordHistory> historyRecords = new ArrayList<>();
        Session session = model.getSession();
        try {
            long sessionId = session.getSessionId();
            List<Integer> historyIds = model.getDb().getTableHistory().getHistoryIds(sessionId);
            for (Integer historyId : historyIds) {
                if(historyId < startAtHistoryId){
                    continue;
                }

                RecordHistory record = model.getDb().getTableHistory().read(historyId);
                historyRecords.add(record);
            }
        } catch (DatabaseException | HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return historyRecords;
    }

    public void setDateTimeFormatterPattern(String dateTimeFormatterPattern) {
        this.dateTimeFormatterPattern = dateTimeFormatterPattern;
    }

    public void setDateTimeFormatterZone(String dateTimeFormatterZone) {
        this.dateTimeFormatterZone = dateTimeFormatterZone;
    }

    public void setDateTimeToleranceInMs(int dateTimeToleranceInMs) {
        this.dateTimeToleranceInMs = dateTimeToleranceInMs;
    }

    public void setModel(Model model){
        this.model = model;
    }

    public void setDateTimeOffsetInMs(int dateTimeOffsetInMs) {
        this.dateTimeOffsetInMs = dateTimeOffsetInMs;
    }
}
