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

import org.zaproxy.zap.extension.logreader.LinkedApplicationLogMessage;
import org.zaproxy.zap.view.ZapTable;

import java.util.List;

public class ApplicationLogTable extends ZapTable {

    private static final long serialVersionUID = 1L;
    private ApplicationLogTableModel tableModel;

    public static final String TABLE_NAME = "Application Log Table";

    public ApplicationLogTable(ApplicationLogTableModel tableModel) {
        super(tableModel);
        this.tableModel = tableModel;

        setAutoCreateColumnsFromModel(false);

        setName(TABLE_NAME);

        getColumnExt(ApplicationLogTableModel.TIMESTAMP).setPreferredWidth(20);
        getColumnExt(ApplicationLogTableModel.TIMESTAMP).setWidth(20);
        getColumnExt(ApplicationLogTableModel.LEVEL).setPreferredWidth(20);
        getColumnExt(ApplicationLogTableModel.LEVEL).setWidth(20);
        getColumnExt(ApplicationLogTableModel.MESSAGE).setPreferredWidth(500);
        getColumnExt(ApplicationLogTableModel.MESSAGE).setWidth(500);
    }

    public List<LinkedApplicationLogMessage> getSelectedLogs(){
        return tableModel.getModelsByIndex(this.getSelectedRows());
    }
}
