/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;
import java.util.Map;

import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.AbstractHttpFuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler.FuzzerHttpMessageScriptProcessorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.DynamicFieldsPanel;
import org.zaproxy.zap.view.LayoutHelper;

public class FuzzerHttpMessageScriptProcessorAdapterUIHandler implements
		HttpFuzzerMessageProcessorUIHandler<FuzzerHttpMessageScriptProcessorAdapter, FuzzerHttpMessageScriptProcessorAdapterUI> {

	private static final String PROCESSOR_NAME = Constant.messages
			.getString("fuzz.httpfuzzer.processor.scriptProcessor.name");

	private final ExtensionScript extensionScript;

	public FuzzerHttpMessageScriptProcessorAdapterUIHandler(ExtensionScript extensionScript) {
		this.extensionScript = extensionScript;
	}

	@Override
	public boolean isEnabled(HttpMessage message) {
		return true;
	}

	@Override
	public boolean isDefault() {
		return false;
	}

	@Override
	public FuzzerHttpMessageScriptProcessorAdapterUI createDefault() {
		return null;
	}

	@Override
	public String getName() {
		return PROCESSOR_NAME;
	}

	@Override
	public Class<HttpMessage> getMessageType() {
		return HttpMessage.class;
	}

	@Override
	public Class<FuzzerHttpMessageScriptProcessorAdapter> getFuzzerMessageProcessorType() {
		return FuzzerHttpMessageScriptProcessorAdapter.class;
	}

	@Override
	public Class<FuzzerHttpMessageScriptProcessorAdapterUI> getFuzzerMessageProcessorUIType() {
		return FuzzerHttpMessageScriptProcessorAdapterUI.class;
	}

	@Override
	public FuzzerHttpMessageScriptProcessorAdapterUIPanel createPanel() {
		return new FuzzerHttpMessageScriptProcessorAdapterUIPanel(
				extensionScript.getScripts(HttpFuzzerProcessorScriptProxy.TYPE_NAME));
	}

	public static class FuzzerHttpMessageScriptProcessorAdapterUI
			implements HttpFuzzerMessageProcessorUI<FuzzerHttpMessageScriptProcessorAdapter> {

		private final ScriptWrapper scriptWrapper;
		private final Map<String, String> paramsValues;

		public FuzzerHttpMessageScriptProcessorAdapterUI(ScriptWrapper scriptWrapper, Map<String, String> paramsValues) {
			this.scriptWrapper = scriptWrapper;
			this.paramsValues = paramsValues;
		}

		public ScriptWrapper getScriptWrapper() {
			return scriptWrapper;
		}

		@Override
		public boolean isMutable() {
			return true;
		}

		@Override
		public String getName() {
			return PROCESSOR_NAME;
		}

		@Override
		public String getDescription() {
			return scriptWrapper.getName();
		}

		@Override
		public FuzzerHttpMessageScriptProcessorAdapter getFuzzerMessageProcessor() {
			
			return new FuzzerHttpMessageScriptProcessorAdapter(scriptWrapper, paramsValues);
		}

		@Override
		public FuzzerHttpMessageScriptProcessorAdapterUI copy() {
			return new FuzzerHttpMessageScriptProcessorAdapterUI(scriptWrapper, paramsValues);
		}
	}

	public static class FuzzerHttpMessageScriptProcessorAdapterUIPanel extends
			AbstractHttpFuzzerMessageProcessorUIPanel<FuzzerHttpMessageScriptProcessorAdapter, FuzzerHttpMessageScriptProcessorAdapterUI> {

		private static final String SCRIPT_FIELD_LABEL = Constant.messages
				.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.script.label");
		private static final Logger log = Logger.getLogger(FuzzerHttpMessageScriptProcessorAdapterUIPanel.class);
		private final JPanel mainPanel;
		private final JComboBox<ScriptUIEntry> scriptComboBox;
		private DynamicFieldsPanel dynamicFieldsPanel;

		public FuzzerHttpMessageScriptProcessorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
			mainPanel = new JPanel();
			mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
			scriptComboBox = new JComboBox<>(new SortedComboBoxModel<ScriptUIEntry>());
			addScriptsToScriptComboBox(scriptWrappers);
			addScriptComboBoxItemChangedListener();			
			renderScriptChoicePanel();			
			renderFieldsPanelForScriptParameters();
		}

		private void addScriptsToScriptComboBox(List<ScriptWrapper> scriptWrappers) {
			for (ScriptWrapper scriptWrapper : scriptWrappers) {
				if (scriptWrapper.isEnabled()) {
					scriptComboBox.addItem(new ScriptUIEntry(scriptWrapper));
				}
			}
		}

		private void addScriptComboBoxItemChangedListener() {
			scriptComboBox.addItemListener(new ItemListener() {
				@Override
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {
						renderFieldsPanelForScriptParameters();
					}
				}
			});
		}

		private void renderScriptChoicePanel() {
			JPanel scriptChoicePanel = new JPanel();
			GroupLayout layout = new GroupLayout(scriptChoicePanel);
			scriptChoicePanel.setLayout(layout);
			layout.setAutoCreateGaps(true);

			JLabel scriptLabel = new JLabel(SCRIPT_FIELD_LABEL);
			scriptLabel.setLabelFor(scriptComboBox);

			layout.setHorizontalGroup(
					layout.createSequentialGroup().addComponent(scriptLabel).addComponent(scriptComboBox));

			layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(scriptLabel)
					.addComponent(scriptComboBox));

			scriptChoicePanel
					.setMaximumSize(new Dimension(Integer.MAX_VALUE, scriptChoicePanel.getPreferredSize().height));
			mainPanel.add(scriptChoicePanel);
		}

		private void renderFieldsPanelForScriptParameters() {
			ScriptUIEntry scriptUIEntry = (ScriptUIEntry) scriptComboBox.getSelectedItem();
			String[] requiredParameters = new String[0];
			String[] optionalParameters = new String[0];

			try {
				HttpFuzzerProcessorScriptProxy proxy = HttpFuzzerProcessorScriptProxy
						.create(scriptUIEntry.getScriptWrapper());
				requiredParameters = proxy.getRequiredParamsNames();
				optionalParameters = proxy.getOptionalParamsNames();
			} catch (Exception ex) {
				log.info("Script '" + scriptUIEntry.scriptWrapper.getName() + "' can not load parameters. " + ex.getMessage());				
			}

			if (mainPanel.getComponentCount() > 1) {
				mainPanel.remove(1);
			}
			
			dynamicFieldsPanel = new DynamicFieldsPanel(requiredParameters, optionalParameters);				
			if (requiredParameters.length > 0 || optionalParameters.length > 0) {
				alignFieldsToTheTop(dynamicFieldsPanel, requiredParameters.length + optionalParameters.length);		
				JScrollPane scrollPane = new JScrollPane(dynamicFieldsPanel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				mainPanel.add(scrollPane);
			}			

			mainPanel.revalidate();
			mainPanel.repaint();		
		}
		
		private void alignFieldsToTheTop(DynamicFieldsPanel dynamicFieldsPanel, int fieldsCount) {
			GridBagLayout gridBagLayout = (GridBagLayout)dynamicFieldsPanel.getLayout();				    		    
			int newRowCount = fieldsCount + 1;
			int lastRowIndex = newRowCount - 1;
			double[] rowWeights = new double[newRowCount];
			for (int i = 0; i < newRowCount; i++) {
				rowWeights[i] = 0.0;
			}
			
			rowWeights[lastRowIndex] = 1.0;			
			dynamicFieldsPanel.add(new JPanel(), LayoutHelper.getGBC(0, lastRowIndex, 2, 0.0d, 0.0d));
			gridBagLayout.rowWeights = rowWeights;		
		}

		@Override
		public JPanel getComponent() {
			return mainPanel;
		}

		@Override
		public void setFuzzerMessageProcessorUI(FuzzerHttpMessageScriptProcessorAdapterUI payloadProcessorUI) {
			scriptComboBox.setSelectedItem(new ScriptUIEntry(payloadProcessorUI.getScriptWrapper()));						
			dynamicFieldsPanel.bindFieldValues(payloadProcessorUI.paramsValues);
		}

		@Override
		public FuzzerHttpMessageScriptProcessorAdapterUI getFuzzerMessageProcessorUI() {
			Map<String, String> paramValues = dynamicFieldsPanel.getFieldValues();
			ScriptWrapper scriptWrapper = ((ScriptUIEntry) scriptComboBox.getSelectedItem()).getScriptWrapper();
			return new FuzzerHttpMessageScriptProcessorAdapterUI(scriptWrapper, paramValues);
		}

		@Override
		public void clear() {
			scriptComboBox.setSelectedIndex(-1);
		}

		@Override
		public boolean validate() {
			if (scriptComboBox.getSelectedIndex() == -1) {
				showValidationMessageDialog(
						Constant.messages
						.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.message"),
						Constant.messages
						.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.title"));
				return false;
			}			
			
			try {
				dynamicFieldsPanel.validateFields();
			} catch (IllegalStateException ex) {
				showValidationMessageDialog(ex.getMessage(),
						Constant.messages
						.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warn.title"));
				return false;
			}
			
			return true;
		}
		
		private void showValidationMessageDialog(Object message,String title){
			JOptionPane.showMessageDialog(null, message, title, JOptionPane.INFORMATION_MESSAGE);
			scriptComboBox.requestFocusInWindow();
		}

		private static class ScriptUIEntry implements Comparable<ScriptUIEntry> {

			private final ScriptWrapper scriptWrapper;
			private final String scriptName;

			public ScriptUIEntry(ScriptWrapper scriptWrapper) {
				this.scriptWrapper = scriptWrapper;
				this.scriptName = scriptWrapper.getName();
				if (scriptName == null) {
					throw new IllegalArgumentException("Script must have a name.");
				}
			}

			public ScriptWrapper getScriptWrapper() {
				return scriptWrapper;
			}

			@Override
			public String toString() {
				return scriptName;
			}

			@Override
			public int hashCode() {
				final int prime = 31;
				int result = 1;
				result = prime * result + ((scriptName == null) ? 0 : scriptName.hashCode());
				return result;
			}

			@Override
			public boolean equals(Object obj) {
				if (this == obj) {
					return true;
				}
				if (obj == null) {
					return false;
				}
				if (getClass() != obj.getClass()) {
					return false;
				}
				ScriptUIEntry other = (ScriptUIEntry) obj;
				if (scriptName == null) {
					if (other.scriptName != null) {
						return false;
					}
				} else if (!scriptName.equals(other.scriptName)) {
					return false;
				}
				return true;
			}

			@Override
			public int compareTo(ScriptUIEntry other) {
				if (other == null) {
					return 1;
				}
				return scriptName.compareTo(other.scriptName);
			}

		}
	}
}
