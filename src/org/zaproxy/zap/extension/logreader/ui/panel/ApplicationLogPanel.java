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
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.logreader.ExtensionLogReader;
import org.zaproxy.zap.extension.logreader.LinkedApplicationLogMessage;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.TableExportButton;
import org.zaproxy.zap.view.ZapToggleButton;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class ApplicationLogPanel extends AbstractPanel {

	public static final String PANEL_NAME = "Application Log Panel";
	private static final long serialVersionUID = 1L;

	private javax.swing.JScrollPane scrollLog = null;
	private ApplicationLogTable applicationLogTable = null;
	private javax.swing.JPanel historyPanel = null;
	private javax.swing.JToolBar panelToolbar = null;
	private ExtensionLogReader extensionLogReader;
	private ApplicationLogTableModel tableModel;
	private ZapToggleButton filterButton = null;
	private JButton optionsButton;
	private TableExportButton<JTable> exportButton;

	public ApplicationLogPanel(ExtensionLogReader extensionLogReader, ApplicationLogTableModel tableModel) {
		super();
		this.extensionLogReader = extensionLogReader;
		this.tableModel = tableModel;
		initialize();
	}

	/**
	 * This method initializes this
	 */
	private  void initialize() {
		this.setLayout(new BorderLayout());
	    if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
	    	this.setSize(600, 200);
	    }
		this.add(getHistoryPanel(), BorderLayout.CENTER);
	}

	@Override
	public void tabSelected() {
		// Give focus so that the user can immediately use the arrow keys to navigate
	    getApplicationLogTable().requestFocusInWindow();
	}

	private javax.swing.JScrollPane getScrollLog() {
		if (scrollLog == null) {
			scrollLog = new javax.swing.JScrollPane();
			scrollLog.setViewportView(getApplicationLogTable());
			scrollLog.setName("scrollLog");
		}
		return scrollLog;
	}

	private javax.swing.JPanel getHistoryPanel() {
		if (historyPanel == null) {

			historyPanel = new javax.swing.JPanel();
			historyPanel.setLayout(new java.awt.GridBagLayout());
			historyPanel.setName(PANEL_NAME);

			GridBagConstraints gridBagConstraintsToolbar = new GridBagConstraints();
			GridBagConstraints gridBagConstraintsScroll = new GridBagConstraints();

			gridBagConstraintsToolbar.gridx = 0;
			gridBagConstraintsToolbar.gridy = 0;
			gridBagConstraintsToolbar.weightx = 1.0D;
			gridBagConstraintsToolbar.insets = new java.awt.Insets(2,2,2,2);
			gridBagConstraintsToolbar.fill = GridBagConstraints.HORIZONTAL;
			gridBagConstraintsToolbar.anchor = GridBagConstraints.NORTHWEST;

			gridBagConstraintsScroll.gridx = 0;
			gridBagConstraintsScroll.gridy = 1;
			gridBagConstraintsScroll.weightx = 1.0;
			gridBagConstraintsScroll.weighty = 1.0;
			gridBagConstraintsScroll.insets = new java.awt.Insets(0,0,0,0);
			gridBagConstraintsScroll.fill = GridBagConstraints.BOTH;
			gridBagConstraintsScroll.anchor = GridBagConstraints.NORTHWEST;

			historyPanel.add(this.getPanelToolbar(), gridBagConstraintsToolbar);
			historyPanel.add(getScrollLog(), gridBagConstraintsScroll);

		}
		return historyPanel;
	}

	private javax.swing.JToolBar getPanelToolbar() {
		if (panelToolbar == null) {
			panelToolbar = new javax.swing.JToolBar();
			panelToolbar.setLayout(new java.awt.GridBagLayout());
			panelToolbar.setEnabled(true);
			panelToolbar.setFloatable(false);
			panelToolbar.setRollover(true);
			panelToolbar.setPreferredSize(new java.awt.Dimension(800,30));
			panelToolbar.setName("Application Log Toolbar");

			GridBagConstraints gridBagConstraintsX = newGBC(20);
			gridBagConstraintsX.weightx = 1.0;
			gridBagConstraintsX.weighty = 1.0;
			gridBagConstraintsX.anchor = java.awt.GridBagConstraints.EAST;
			gridBagConstraintsX.fill = java.awt.GridBagConstraints.HORIZONTAL;

			GridBagConstraints optionsGridBag = newGBC(gridBagConstraintsX.gridx +1);
			optionsGridBag.anchor = java.awt.GridBagConstraints.EAST;

			panelToolbar.add(getFilterButton(), newGBC(0));
			panelToolbar.add(new JLabel(), gridBagConstraintsX);
			panelToolbar.add(getExportButton(), newGBC(1));
			panelToolbar.add(getOptionsButton(), optionsGridBag);
		}
		return panelToolbar;
	}

	private GridBagConstraints newGBC (int gridX) {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.gridx = gridX;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.insets = new java.awt.Insets(0,0,0,0);
		gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
		return gridBagConstraints;
	}

	private TableExportButton<JTable> getExportButton() {
		if (exportButton == null) {
			exportButton = new TableExportButton<>(applicationLogTable);
		}
		return exportButton;
	}

	private JButton getOptionsButton() {
		if (optionsButton == null) {
			optionsButton = new JButton();
			optionsButton.setToolTipText(Constant.messages.getString("logreader.panel.toolbar.button.options"));
			optionsButton.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(ApplicationLogPanel.class.getResource("/resource/icon/16/041.png"))));
			optionsButton.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					Control.getSingleton()
							.getMenuToolsControl()
							.options(Constant.messages.getString("logreader.options.title"));
				}
			});
		}
		return optionsButton;
	}

	private ApplicationLogTable getApplicationLogTable() {
		if (applicationLogTable == null) {
			applicationLogTable = new ApplicationLogTable(tableModel);
			applicationLogTable.addMouseListener(new java.awt.event.MouseAdapter() {

				@Override
				public void mouseClicked(java.awt.event.MouseEvent e) {
				if (SwingUtilities.isLeftMouseButton(e) && e.getClickCount() > 1) {  // double click
					extensionLogReader.openSearchForSelectedLinkedHttpMessages();
				}
				}
			});

			applicationLogTable.addMouseListener(new java.awt.event.MouseAdapter() {
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
					showPopupMenuIfTriggered(e);
				}
				@Override
				public void mouseReleased(java.awt.event.MouseEvent e) {
					showPopupMenuIfTriggered(e);
				}

				private void showPopupMenuIfTriggered(java.awt.event.MouseEvent e) {
					if (e.isPopupTrigger()) {
						View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
					}
				}
			});
		}
		return applicationLogTable;
	}

	private JToggleButton getFilterButton() {
		if (filterButton == null) {
			filterButton = new ZapToggleButton();
			filterButton.setIcon(new ImageIcon(ApplicationLogPanel.class.getResource("/org/zaproxy/zap/extension/logreader/resources/funnel_disabled.png"))); //filter icon
			filterButton.setToolTipText(Constant.messages.getString("logreader.panel.toolbar.filter.enable.tooltip"));
			filterButton.setSelectedIcon(new ImageIcon(ApplicationLogPanel.class.getResource("/org/zaproxy/zap/extension/logreader/resources/funnel_enabled.png"))); //filter icon
			filterButton.setSelectedToolTipText(Constant.messages.getString("logreader.panel.toolbar.filter.disable.tooltip"));
			DisplayUtils.scaleIcon(filterButton);

			filterButton.addActionListener(new java.awt.event.ActionListener() {

				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					//foo
				}
			});
		}
		return filterButton;
	}


	public List<LinkedApplicationLogMessage> getSelectedLogs(){
		return getApplicationLogTable().getSelectedLogs();
	}
}
