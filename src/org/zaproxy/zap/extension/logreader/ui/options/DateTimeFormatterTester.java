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

package org.zaproxy.zap.extension.logreader.ui.options;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.logreader.DateTimeParser;
import org.zaproxy.zap.view.StandardFieldsDialog;

import javax.swing.JLabel;
import java.awt.Dimension;
import java.awt.Window;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class DateTimeFormatterTester extends StandardFieldsDialog {

    private static final Logger LOGGER = Logger.getLogger(DateTimeFormatterTester.class);
    public static final String FIELD_PATTERN = "logreader.datetimeformattertester.dialog.field.pattern";
    public static final String FIELD_ZONE = "logreader.datetimeformattertester.dialog.field.zone";
    public static final String FIELD_DATE = "logreader.datetimeformattertester.dialog.field.date";
    public static final String FIELD_OUT = "logreader.datetimeformattertester.dialog.field.dateout";

    private static final long serialVersionUID = 1L;

    public DateTimeFormatterTester(Window owner, Dimension dim) {
        super(owner, "logreader.datetimeformattertester.dialog.name", dim);;
    }

    public void initialize(String pattern, String zone) {
        this.removeAllFields();
        this.setTitle(Constant.messages.getString("logreader.datetimeformattertester.dialog.name"));
        this.setDefaultCloseOperation(2);
        this.setHideOnSave(false);

        this.addTextField(FIELD_PATTERN, pattern);
        this.addTextField(FIELD_ZONE, zone);
        this.addTextField(FIELD_DATE, tryCreateDemoDate(pattern));
        this.addReadOnlyField(FIELD_OUT,"", false);
    }

    private String tryCreateDemoDate(String pattern){
        try{
            return ZonedDateTime.now().format(DateTimeParser.getDateTimeFormatterOfPattern(pattern));
        }catch (Exception e){
            return "";
        }
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("logreader.datetimeformattertester.dialog.button.test");
    }

    @Override
    public void save() {
        String pattern = this.getStringValue(FIELD_PATTERN);
        String zone = this.getStringValue(FIELD_ZONE);
        String date = this.getStringValue(FIELD_DATE);

        try {
            LocalDateTime localDateTime = DateTimeParser.parseToUtc(date, pattern, zone);
            String formattedOutDate = DateTimeFormatter.ISO_DATE_TIME.format(localDateTime);
            getReadOnlyField(FIELD_OUT).setText(formattedOutDate);
        }
        catch (DateTimeParseException e) {
            LOGGER.error(e.getMessage(),e);
            getReadOnlyField(FIELD_OUT).setText("");
            View.getSingleton().showWarningDialog("'"+date+"' is not parsable with pattern '" + pattern + "' !\n\nError:\n" + e.getMessage());
        }catch (Exception e){
            getReadOnlyField(FIELD_OUT).setText("");
            View.getSingleton().showWarningDialog(e.getMessage());
            LOGGER.error(e.getMessage(),e);
        }
    }

    private JLabel getReadOnlyField(String key) {
        return (JLabel)this.getField(key);
    }

    @Override
    public String validateFields() {
        return null;
    }
}
