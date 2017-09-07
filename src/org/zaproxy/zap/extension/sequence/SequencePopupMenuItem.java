package org.zaproxy.zap.extension.sequence;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.network.DefaultHttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.net.URLDecoder;
import java.text.MessageFormat;
import java.util.List;

public class SequencePopupMenuItem extends ExtensionPopupMenu {

	private static final long serialVersionUID = 1L;
	
	private final ExtensionScript extensionScript;
	public static final Logger logger = Logger.getLogger(SequencePopupMenuItem.class);
	private ExtensionSequence extensionSequence = null;

	// TODO Replace the value (17) with HistoryReference.TYPE_SEQUENCE_TEMPORARY once released with core
	private static final int SEQUENCE_HISTORY_TYPE = 17;
	private ExtensionHistory extensionHistory;
	private ExtensionActiveScan extensionActiveScan;

	public SequencePopupMenuItem(ExtensionSequence extensionSequence, ExtensionScript extensionScript, ExtensionHistory extensionHistory, ExtensionActiveScan extensionActiveScan) {
		super();
		this.extensionSequence = extensionSequence;
		this.extensionScript = extensionScript;
		this.extensionHistory = extensionHistory;
		this.extensionActiveScan = extensionActiveScan;
		initialize();
	}

	private void initialize() {
		this.setText(extensionSequence.getMessages().getString("sequence.popupmenuitem.activeScanSequence"));
		this.addMenuListener(new MenuListener() {
			@Override
			public void menuSelected(MenuEvent e) {
				addItems();
			}

			@Override
			public void menuDeselected(MenuEvent e) {

			}

			@Override
			public void menuCanceled(MenuEvent e) {

			}
		});
	}

	@Override
	public int getMenuIndex() {
		return 2;
	}

	private void addItems(){
		SequenceScript selectedScript = getSelectedSequenceScript();
		List<HttpMessage> httpMessages = selectedScript.getAllRequestsInScript();
		this.removeAll();
		addRunAllItem();
		int messageIndex = 0;
		for (HttpMessage message : httpMessages) {
			addItem(message, messageIndex++);
		}
	}

	private void addItem(HttpMessage message, int messageIndex){
		final int localMessageIndex = messageIndex;
		int messageNumber = messageIndex+1;
		String uri = getUrlDecodedUri(message);
		JMenuItem item = new JMenuItem(messageNumber + ": " + message.getRequestHeader().getMethod() + " " + uri);
		this.add(item);

		item.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				startActiveScanner(localMessageIndex);
			}
		});
	}

	private void addRunAllItem(){
		final SequenceScript localScript = getSelectedSequenceScript();
		JMenuItem item = new JMenuItem("Run all");
		this.add(item);

		item.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				localScript.scanSequence();
			}
		});
	}

	private SequenceScript getSelectedSequenceScript() {
		return getSelectedSequenceScript(-1);
	}

	private SequenceScript getSelectedSequenceScript(int indexOfMessage) {
		ScriptWrapper wrapper = getSelectedScript();
		SequenceScript  sequenceScript = tryGetSequenceScript(indexOfMessage, wrapper);
		if (sequenceScript == null) {
			String msg = Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence.script.error.interface");
			View.getSingleton().showMessageDialog(MessageFormat.format(msg, wrapper.getName()));
		}
		return sequenceScript;
	}

	private SequenceScript tryGetSequenceScript(int indexOfMessage, ScriptWrapper wrapper) {
		try {
			if(wrapper.getClass().getName() == "org.zaproxy.zap.extension.zest.ZestScriptWrapper" && indexOfMessage >= 0){
				Class zestScriptWrapperClass = Class.forName("org.zaproxy.zap.extension.zest.ZestScriptWrapper");
				Class extensionZestClass = Class.forName("org.zaproxy.zap.extension.zest.ExtensionZest");
				Extension extensionZest = Control.getSingleton().getExtensionLoader().getExtension(extensionZestClass);
				Class<?> zestIndexBasedSequenceRunnerClass = Class.forName("org.zaproxy.zap.extension.zest.ZestIndexBasedSequenceRunner");
				Constructor<?> cons = zestIndexBasedSequenceRunnerClass.getConstructor(extensionZestClass, zestScriptWrapperClass, int.class);
				return (SequenceScript)cons.newInstance(extensionZest, wrapper, indexOfMessage);
			}
			return extensionScript.getInterface(wrapper, SequenceScript.class);
		}catch (Exception ex){
			logger.error("Error while trying to get the SequenceScript from the selected node", ex);
			return null;
		}
	}

	private ScriptWrapper getSelectedScript() {
		return (ScriptWrapper) getSelectedNode().getUserObject();
	}


	private void startActiveScanner(int index) {
		try {
			SequenceScript sequenceScript = getSelectedSequenceScript(index);
			SiteNode node = createTargetToScanOneRequestOfSequence(sequenceScript, index);
			extensionSequence.setDirectScanScript(sequenceScript);
			extensionActiveScan.showCustomScanDialog(node);
		}catch (Exception ex){
			String msg = Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence.script.error.starting.scanner");
			View.getSingleton().showMessageDialog(msg);
			logger.error("Error while starting Active Scanner for Sequence Request", ex);
		}
	}

	private SiteNode createTargetToScanOneRequestOfSequence(SequenceScript script, int index) throws IOException, DatabaseException {
		HttpMessage msg = script.getAllRequestsInScript().get(index);
		msg = sendAndReceiveOriginalHttpMessage(script, msg);
		return messageToSiteNode(msg, index);
	}

	// Run the Sequence Script before scanner to have a baseline (originalMessage)
	private HttpMessage sendAndReceiveOriginalHttpMessage(SequenceScript sequenceScript, HttpMessage originalHttpMessage) throws IOException {
		HttpSender httpSender = createHttpSender();
		HttpMessage tmpHttpMessage = sequenceScript.runSequenceBefore(originalHttpMessage.cloneAll(), null);
		HttpRequestConfig config = HttpRequestConfig
				.builder()
				.setRedirectionValidator(DefaultHttpRedirectionValidator.INSTANCE)
				.setFollowRedirects(true)
				.build();
		httpSender.sendAndReceive(tmpHttpMessage, config);
		sequenceScript.runSequenceAfter(tmpHttpMessage, null);

		// Copy only the Response to HttpMessage template for scanner
		// Request may contain variables
		originalHttpMessage.setResponseHeader(tmpHttpMessage.getResponseHeader());
		originalHttpMessage.setResponseBody(tmpHttpMessage.getResponseBody());
		return originalHttpMessage;
	}

	private HttpSender createHttpSender() {
		HttpSender httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, HttpSender.ACTIVE_SCANNER_INITIATOR);
		//ToDo: (Question) How can we get the current user from the dialog....?
		//httpSender.setUser(this.user);
		httpSender.setRemoveUserDefinedAuthHeaders(true);
		return httpSender;
	}

	private SiteNode messageToSiteNode(HttpMessage msg, int messageIndex) throws DatabaseException, HttpMalformedHeaderException {
		int messageNumber = messageIndex+1;
		String uri = getUrlDecodedUri(msg);
		String name = messageNumber + ": " + msg.getRequestHeader().getMethod() + " " + uri;

		SiteNode fakeRoot = new SiteNode(null, SEQUENCE_HISTORY_TYPE, "FakeRoot");
		SiteNode temp = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);
		fakeRoot.add(temp);
		HistoryReference ref = new HistoryReference(extensionHistory.getModel().getSession(), SEQUENCE_HISTORY_TYPE, msg);
		extensionHistory.addHistory(ref);
		temp.setHistoryReference(ref);
		return temp;
	}

	private String getUrlDecodedUri(HttpMessage message){
		String uri = message.getRequestHeader().getURI().toString();
		try {
			return URLDecoder.decode(uri, "UTF8");
		} catch (UnsupportedEncodingException e) {
			return uri;
		}
	}

	@Override
	public boolean isEnableForComponent(Component component) {
		return isScriptTree(component) &&
				isNotATemplate() &&
				isSequenceScript() &&
				isScriptWrapperWithEngine();
	}

	private boolean isNotATemplate() {
		ScriptNode node = getSelectedNode();
		return node != null && !node.isTemplate();
	}

	private ScriptNode getSelectedNode() {
		return extensionScript.getScriptUI().getSelectedNode();
	}

	private boolean isSequenceScript() {
		ScriptNode node = getSelectedNode();
		return node != null && node.getType() != null && node.getType().getName().equals(ExtensionSequence.TYPE_SEQUENCE);
	}

	private boolean isScriptWrapperWithEngine(){
		ScriptNode node = getSelectedNode();
		return node.getUserObject() != null && node.getUserObject() instanceof ScriptWrapper && ((ScriptWrapper) node.getUserObject()).getEngine() != null;
	}

	private boolean isScriptTree(Component component) {
		return this.extensionScript.getScriptUI() != null
				&& component != null
				&& this.extensionScript.getScriptUI().getTreeName()
				.equals(component.getName());
	}
}
