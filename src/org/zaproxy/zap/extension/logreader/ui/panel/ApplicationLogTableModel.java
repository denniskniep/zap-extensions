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
package org.zaproxy.zap.extension.logreader.ui.panel;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.logreader.LinkedApplicationLogMessage;
import org.zaproxy.zap.extension.logreader.handler.ApplicationLogMessageReceivedHandler;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * A {@code DefaultHistoryReferencesTableModel} for History tab.
 */
public class ApplicationLogTableModel extends AbstractTableModel implements ApplicationLogMessageReceivedHandler {

    public static final String TIMESTAMP = Constant.messages.getString("logreader.panel.columns.timestamp");
    public static final String LEVEL = Constant.messages.getString("logreader.panel.columns.level");
    public static final String MESSAGE = Constant.messages.getString("logreader.panel.columns.message");
    public static final String LINK_COUNT = Constant.messages.getString("logreader.panel.columns.linkcount");

    private static final long serialVersionUID = 1L;

    private final Column[] COLUMNS = new Column[]{
           new Column(TIMESTAMP, String.class, (m) -> m.getLogMessage().getTimestamp()),
           new Column(LEVEL, String.class, (m) -> m.getLogMessage().getLevel()),
           new Column(MESSAGE, String.class, (m) -> m.getLogMessage().getMessage()),
           new Column(LINK_COUNT, Integer.class, (m) -> m.getHistoryIdLinks().size())
    };

    private List<LinkedApplicationLogMessage> messages;

    public ApplicationLogTableModel() {
        this.messages = new ArrayList<>();
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMNS[columnIndex].getName();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMNS[columnIndex].getType();
    }

    @Override
    public int getRowCount() {
        return messages.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Column column = COLUMNS[columnIndex];
        LinkedApplicationLogMessage message = messages.get(rowIndex);
        return column.getValue(message);
    }

    @Override
    public void handleLogReceived(LinkedApplicationLogMessage logToHttpMessage) {
        add(logToHttpMessage);
    }

    public void add(LinkedApplicationLogMessage logToHttpMessage){
        messages.add(logToHttpMessage);
        int newIndex = messages.size() - 1;
        fireTableRowsInserted(newIndex, newIndex);
    }

    public static class Column {
        private String name;
        private Class<?> type;
        private Function<LinkedApplicationLogMessage, Object> get;

        public Column(String name, Class<?> type, Function<LinkedApplicationLogMessage, Object> get) {
            this.name = name;
            this.type = type;
            this.get = get;
        }

        public String getName() {
            return name;
        }

        public Class<?> getType() {
            return type;
        }

        public Object getValue(LinkedApplicationLogMessage linkedLogMessage) {
            return get.apply(linkedLogMessage);
        }
    }

    public List<LinkedApplicationLogMessage> getModelsByIndex(int[] rows){
        List<LinkedApplicationLogMessage> models = new ArrayList<>();
        for (int rowIndex : rows) {
            if(rowIndex >= 0 && rowIndex < messages.size()){
                LinkedApplicationLogMessage message = messages.get(rowIndex);
                models.add(message);
            }
        }
        return models;
    }
}
