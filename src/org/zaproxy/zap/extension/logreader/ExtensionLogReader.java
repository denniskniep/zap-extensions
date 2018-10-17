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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyServer;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.logreader.handler.ApplicationLogMessageReceivedHandler;
import org.zaproxy.zap.extension.logreader.handler.LogMessageInMemoryStore;
import org.zaproxy.zap.extension.logreader.linker.DummyLinker;
import org.zaproxy.zap.extension.logreader.linker.TimebasedLinker;
import org.zaproxy.zap.extension.logreader.ui.PopupMenuOpenSearch;
import org.zaproxy.zap.extension.logreader.ui.options.OptionsLogReaderPanel;
import org.zaproxy.zap.extension.logreader.ui.panel.ApplicationLogPanel;
import org.zaproxy.zap.extension.logreader.ui.panel.ApplicationLogTableModel;
import org.zaproxy.zap.extension.search.ExtensionSearch;

import javax.swing.ImageIcon;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ExtensionLogReader extends ExtensionAdaptor implements OptionsChangedListener {

	private static final Logger LOGGER = Logger.getLogger(ExtensionLogReader.class);
	public static final String NAME = "ExtensionLogReader";
	public static final int EXTENSION_ORDER = 86;
	public static final ImageIcon LOG_READER_ICON;

	private ApplicationLogTableModel applicationLogTableModel;
	private ProxyServer proxyServer;
	private ApplicationLogManager applicationLogManager;
	private LogMessageInMemoryStore logMessageStore;

	private LogReaderParam callbackParam;
	private OptionsLogReaderPanel optionsCallbackPanel;

	private ExtensionSearch extensionSearch;

	private String currentConfigLocalAddress;
	private int currentConfigPort;

	static {
		LOG_READER_ICON = View.isInitialised()
				? new ImageIcon(ExtensionLogReader.class.getResource("/org/zaproxy/zap/extension/logreader/resources/application-text.png"))
				: null;
	}

	private ApplicationLogPanel applicationLogPanel;
	private TimebasedLinker timebasedLinker;
	private PopupMenuOpenSearch popupMenuSearch;

	public ExtensionLogReader() {
		super(NAME);
		this.setOrder(EXTENSION_ORDER);

	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void unload() {
		if(proxyServer != null){
			proxyServer.stopServer();
		}
		super.unload();
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}


	@Override
	public String getUIName() {
		return Constant.messages.getString("logreader.name");
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("logreader.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);
		extensionHook.addOptionsParamSet(getLogReaderParam());
		extensionHook.addOptionsChangedListener(this);
		if (View.isInitialised()) {

			extensionHook.getHookView().addOptionPanel(getOptionsLogReaderPanel());
			extensionHook.getHookView().addStatusPanel(getApplicationLogPanel());

			final ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();
			if (extLoader.isExtensionEnabled(ExtensionSearch.NAME)) {
				extensionSearch = (ExtensionSearch)extLoader.getExtension(ExtensionSearch.NAME);
				extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuOpenSearch());
				extensionSearch.addCustomHttpSearcher(new HistoryIdCustomSearch());
			}
		}
	}

	@Override
	public void init() {
		logMessageStore = new LogMessageInMemoryStore();
		applicationLogTableModel = new ApplicationLogTableModel();
		applicationLogManager = new ApplicationLogManager();
		timebasedLinker = new TimebasedLinker();
		addLogLinker();
		addLogHandler();
		proxyServer = new ProxyServer("ZAP-LogReaderServer");
		proxyServer.addOverrideMessageProxyListener(new LogReaderProxyListener(applicationLogManager));
	}

	@Override
	public void initModel(Model model) {
		super.initModel(model);
		timebasedLinker.setModel(model);
	}

	private void addLogHandler() {
		registerHandler(logMessageStore);
		registerHandler(applicationLogTableModel);
	}

	private void addLogLinker() {
		applicationLogManager.addLinker(new DummyLinker());
		applicationLogManager.addLinker(timebasedLinker);
	}

	@Override
	public void optionsLoaded() {
		proxyServer.setConnectionParam(getModel().getOptionsParam().getConnectionParam());
		currentConfigLocalAddress = this.getLogReaderParam().getLocalAddress();
		currentConfigPort = this.getLogReaderParam().getPort();

		resetTimebasedLinkerOptions();
	}

	private void resetTimebasedLinkerOptions() {
		timebasedLinker.setDateTimeFormatterPattern(this.getLogReaderParam().getLogDateTimeFormatterPattern());
		timebasedLinker.setDateTimeFormatterZone(this.getLogReaderParam().getLogDateTimeFormatterZone());
		timebasedLinker.setDateTimeToleranceInMs(this.getLogReaderParam().getLogDateTimeToleranceInMs());
		timebasedLinker.setDateTimeOffsetInMs(this.getLogReaderParam().getLogDateTimeOffsetInMs());
	}

	@Override
	public void postInit() {
		this.restartServer();
	}

	private void restartServer() {
		// this will close the previous listener (if there was one)
		String address = this.getLogReaderParam().getLocalAddress();
		int port = this.getLogReaderParam().getPort();

		proxyServer.startServer(address, port, false);
		LOGGER.info("Started logreader server on " + address + ":" + port);
	}

	private LogReaderParam getLogReaderParam() {
		if (this.callbackParam == null) {
			this.callbackParam = new LogReaderParam();
		}
		return this.callbackParam;
	}

	private PopupMenuOpenSearch getPopupMenuOpenSearch() {
		if (popupMenuSearch == null) {
			popupMenuSearch = new PopupMenuOpenSearch(this);
		}
		return popupMenuSearch;
	}

	private OptionsLogReaderPanel getOptionsLogReaderPanel() {
		if (optionsCallbackPanel == null) {
			optionsCallbackPanel = new OptionsLogReaderPanel();
		}
		return optionsCallbackPanel;
	}

	@Override
	public void optionsChanged(OptionsParam optionsParam) {
		if (areProxyServerSettingsChanges()) {
			this.restartServer();
			currentConfigLocalAddress = this.getLogReaderParam().getLocalAddress();
			currentConfigPort = this.getLogReaderParam().getPort();
		}

		resetTimebasedLinkerOptions();
	}

	private boolean areProxyServerSettingsChanges() {
		return !currentConfigLocalAddress.equals(
				this.getLogReaderParam().getLocalAddress()) ||
				currentConfigPort != this.getLogReaderParam().getPort();
	}

	public void registerHandler(ApplicationLogMessageReceivedHandler handler) {
		applicationLogManager.registerHandler(handler);
	}

	public void removeHandler(ApplicationLogMessageReceivedHandler handler) {
		applicationLogManager.removeHandler(handler);
	}

	private ApplicationLogPanel getApplicationLogPanel() {
		if (applicationLogPanel == null) {
			applicationLogPanel = new ApplicationLogPanel(this, applicationLogTableModel);
			applicationLogPanel.setName(Constant.messages.getString("logreader.panel.name"));
			applicationLogPanel.setIcon(new ImageIcon(ExtensionLogReader.class.getResource("/org/zaproxy/zap/extension/logreader/resources/application-text.png")));

		}
		return applicationLogPanel;
	}

	public void openSearchForSelectedLinkedHttpMessages() {
		List<LinkedApplicationLogMessage> selectedLogs = applicationLogPanel.getSelectedLogs();
		if(extensionSearch != null && selectedLogs.size() > 0){

			List<String> historyIds = selectedLogs
					.stream()
					.flatMap(l -> l.getHistoryIds().stream())
					.distinct()
					.sorted()
					.map(i -> i.toString())
					.collect(Collectors.toList());

			String filter = String.join(HistoryIdCustomSearch.SEPARATOR, historyIds);
			extensionSearch.search(filter, ExtensionSearch.Type.Custom, HistoryIdCustomSearch.NAME, true, false);
		}
	}
}
