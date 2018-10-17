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

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.logreader.DateTimeParser;
import org.zaproxy.zap.extension.logreader.LogReaderParam;
import org.zaproxy.zap.utils.NetworkUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OptionsLogReaderPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private JPanel panel = null;

    private JComboBox<String> localAddress;
    private ZapPortNumberSpinner port;
    private JCheckBox secure;
    private ZapNumberSpinner logDateTimeToleranceInMs;
    private JComboBox<String> logDateTimeFormatterPattern;
    private JButton logDateTimeFormatterPatternTest;
    private JComboBox<String> logDateTimeFormatterZone;
    private ZapNumberSpinner logDateTimeOffsetInMs;

    public OptionsLogReaderPanel() {
        super();
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("logreader.options.title"));
        this.add(getCallbackPanel(), getCallbackPanel().getName());
    }

    private JPanel getCallbackPanel() {
        if (panel == null) {

            panel = new JPanel();
            panel.setLayout(new GridBagLayout());

            int currentRowIndex = -1;
            addComponent(++currentRowIndex, "logreader.options.label.localaddress", getLocalAddress());
            addComponent(++currentRowIndex, "logreader.options.label.port", getPort());
            addComponent(++currentRowIndex, "logreader.options.label.secure", getSecure());
            addComponent(++currentRowIndex, "logreader.options.label.logdatetimetoleranceinms", getLogDateTimeToleranceInMs());
            addComponent(++currentRowIndex, "logreader.options.label.logdatetimeoffsetinms", getLogDateTimeOffsetInMs());
            addComponent(++currentRowIndex, "logreader.options.label.logdatetimeformatterpattern", getLogDateTimeFormatterPattern());
            addComponent(++currentRowIndex, "logreader.options.label.logdatetimeformatterzone", getLogDateTimeFormatterZone());
            addComponent(++currentRowIndex, "", getLogDateTimeFormatterPatternTest());

            panel.add(new JLabel(), LayoutHelper.getGBC(0, 20, 2, 0.5D, 1.0D));
        }

        return panel;
    }

    private void addComponent(int currentRowIndex, String labelI18nKey, Component component) {
        String text = "";
        if(!labelI18nKey.isEmpty()){
            text = Constant.messages.getString(labelI18nKey);
        }

        JLabel label = new JLabel(text);
        label.setLabelFor(component);
        panel.add(label,
                LayoutHelper.getGBC(0, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        panel.add(component,
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
    }

    private JComboBox<String> getLocalAddress() {
        if (localAddress == null) {
            localAddress = new JComboBox<>();
        }
        return localAddress;
    }

    private JCheckBox getSecure() {
        if (secure == null) {
            secure = new JCheckBox();
        }
        return secure;
    }

    private ZapPortNumberSpinner getPort() {
        if (port == null) {
            port = new ZapPortNumberSpinner(0);
        }
        return port;
    }

    private ZapNumberSpinner getLogDateTimeToleranceInMs() {
        if (logDateTimeToleranceInMs == null) {
            logDateTimeToleranceInMs = new ZapNumberSpinner(0,100, Integer.MAX_VALUE);
        }
        return logDateTimeToleranceInMs;
    }

    private ZapNumberSpinner getLogDateTimeOffsetInMs() {
        if (logDateTimeOffsetInMs == null) {
            logDateTimeOffsetInMs = new ZapNumberSpinner(Integer.MIN_VALUE,0, Integer.MAX_VALUE);
        }
        return logDateTimeOffsetInMs;
    }

    private JComboBox<String> getLogDateTimeFormatterPattern() {
        if (logDateTimeFormatterPattern == null) {
            logDateTimeFormatterPattern = new JComboBox<>();
            logDateTimeFormatterPattern.setEditable(true);
        }
        return logDateTimeFormatterPattern;
    }

    private JButton getLogDateTimeFormatterPatternTest() {
        if (logDateTimeFormatterPatternTest == null) {
            logDateTimeFormatterPatternTest = new JButton();
            logDateTimeFormatterPatternTest.setText(Constant.messages.getString("logreader.options.label.logdatetimeformatterpatterntest"));

            logDateTimeFormatterPatternTest.addActionListener(new java.awt.event.ActionListener() {

                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    DateTimeFormatterTester testerDialog = new DateTimeFormatterTester(
                            SwingUtilities.getWindowAncestor(OptionsLogReaderPanel.this),
                            new Dimension(407, 255));

                    String pattern = logDateTimeFormatterPattern.getSelectedItem() == null ? "" : logDateTimeFormatterPattern.getSelectedItem().toString();
                    String zone = logDateTimeFormatterZone.getSelectedItem() == null ? "" : logDateTimeFormatterZone.getSelectedItem().toString();

                    testerDialog.initialize(pattern, zone);
                    testerDialog.setVisible(true);
                }
            });

        }
        return logDateTimeFormatterPatternTest;
    }

    private JComboBox<String> getLogDateTimeFormatterZone() {
        if (logDateTimeFormatterZone == null) {
            logDateTimeFormatterZone = new JComboBox<>();
            logDateTimeFormatterZone.setEditable(true);
        }
        return logDateTimeFormatterZone;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        LogReaderParam logReaderParam = optionsParam.getParamSet(LogReaderParam.class);

        List<String> allAddrs = NetworkUtils.getAvailableAddresses(false);
        getLocalAddress().removeAllItems();
        getLocalAddress().addItem(LogReaderParam.DEFAULT_IP);
        for (String addr : allAddrs) {
            getLocalAddress().addItem(addr);
        }
        getLocalAddress().setSelectedItem(logReaderParam.getLocalAddress());

        getSecure().setSelected(logReaderParam.isSecure());

        getPort().setValue(logReaderParam.getPort());
        ArrayList<String> formatters = new ArrayList<>(Arrays.asList("yyyy-MM-dd'T'HH:mm:ss.SSS[XXX]"));
        formatters.addAll(DateTimeParser.getPredefinedFormatters());

        getLogDateTimeFormatterPattern().removeAllItems();
        for (String formatter : formatters) {
            getLogDateTimeFormatterPattern().addItem(formatter);
        }
        getLogDateTimeFormatterPattern().setSelectedItem(logReaderParam.getLogDateTimeFormatterPattern());

        String[] zones = new String[]{
                "",
                "UTC",
                "UTC+1"
        };
        getLogDateTimeFormatterZone().removeAllItems();
        for (String zone : zones) {
            getLogDateTimeFormatterZone().addItem(zone);
        }
        getLogDateTimeFormatterZone().setSelectedItem(logReaderParam.getLogDateTimeFormatterZone());

        getLogDateTimeToleranceInMs().setValue(logReaderParam.getLogDateTimeToleranceInMs());

        getLogDateTimeOffsetInMs().setValue(logReaderParam.getLogDateTimeOffsetInMs());
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        Object pattern = getLogDateTimeFormatterPattern().getSelectedItem();
        Object zone = getLogDateTimeFormatterZone().getSelectedItem();

        try{
            DateTimeParser.testPattern(pattern);
        }catch(Exception e){
            throw new Exception(Constant.messages.getString("logreader.options.fail.pattern", e.getMessage()), e);
        }


        if(zone != null && zone instanceof String && !zone.toString().isEmpty())
        {
            try{
                ZoneId.of(zone.toString());
            }catch(Exception e){
                throw new Exception(Constant.messages.getString("logreader.options.fail.zone", e.getMessage()), e);
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        LogReaderParam proxyParam = optionsParam.getParamSet(LogReaderParam.class);

        proxyParam.setLocalAddress((String)getLocalAddress().getSelectedItem());
        proxyParam.setSecure(getSecure().isSelected());
        proxyParam.setPort(getPort().getValue());
        proxyParam.setLogDateTimeToleranceInMs(getLogDateTimeToleranceInMs().getValue());
        proxyParam.setLogDateTimeOffsetInMs(getLogDateTimeOffsetInMs().getValue());
        proxyParam.setLogDateTimeFormatterZone((String)getLogDateTimeFormatterZone().getSelectedItem());
        proxyParam.setLogDateTimeFormatterPattern((String)getLogDateTimeFormatterPattern().getSelectedItem());

    }
}
