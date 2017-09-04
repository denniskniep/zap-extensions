package org.zaproxy.zap.extension.sequence;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.net.URLDecoder;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.ascan.CustomScanDialog;
import org.zaproxy.zap.extension.ascan.CustomScanPanel;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

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
		SequenceScript selectedScript = getSelectedSequenceScript(0);
		List<HttpMessage> httpMessages = selectedScript.getAllRequestsInScript();
		int messageIndex = 0;
		this.removeAll();
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

	private SequenceScript getSelectedSequenceScript(int indexOfMessage) {
		try {
			ScriptWrapper wrapper = getSelectedScript();
			SequenceScript  sequenceScript = tryGetSequenceScript(indexOfMessage, wrapper);
			if (sequenceScript == null) {
				String msg = Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence.script.error.interface");
				View.getSingleton().showMessageDialog(MessageFormat.format(msg, wrapper.getName()));
			}
			return sequenceScript;
		} catch (Exception ex) {
			logger.warn("An exception occurred while starting the fuzzer for a sequence script:", ex);
			return null;
		}
	}

	private SequenceScript tryGetSequenceScript(int indexOfMessage, ScriptWrapper wrapper) throws javax.script.ScriptException, IOException {

		if(wrapper.getClass().getName() == "org.zaproxy.zap.extension.zest.ZestScriptWrapper"){
			try {
				Class zestScriptWrapperClass = Class.forName("org.zaproxy.zap.extension.zest.ZestScriptWrapper");
				Class extensionZestClass = Class.forName("org.zaproxy.zap.extension.zest.ExtensionZest");
				Extension extensionZest = Control.getSingleton().getExtensionLoader().getExtension(extensionZestClass);
				Class<?> zestIndexBasedSequenceRunnerClass = Class.forName("org.zaproxy.zap.extension.zest.ZestIndexBasedSequenceRunner");
				Constructor<?> cons = zestIndexBasedSequenceRunnerClass.getConstructor(extensionZestClass, zestScriptWrapperClass, int.class);
				return (SequenceScript)cons.newInstance(extensionZest, wrapper, indexOfMessage);

			}catch (Exception e){
				return null;
			}
		}

		return extensionScript.getInterface(wrapper, SequenceScript.class);
	}

	private ScriptWrapper getSelectedScript() {
		return (ScriptWrapper) getSelectedNode().getUserObject();
	}
	/*
	private void initialize() {

		
		this.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					ScriptWrapper wrapper = (ScriptWrapper)extensionScript.getScriptUI().getSelectedNode().getUserObject();
					SequenceScript scr = extensionScript.getInterface(wrapper, SequenceScript.class);
					if (scr != null) {
						extensionSequence.setDirectScanScript(wrapper);
						startActiveScanner(wrapper, scr);

						//scr.scanSequence();


					} else {
						String msg = extensionSequence.getMessages().getString("sequence.popupmenuitem.script.error.interface");
						View.getSingleton().showMessageDialog(MessageFormat.format(msg, wrapper.getName()));
					}
				} catch(Exception ex) {
					logger.warn("An exception occurred while starting an active scan for a sequence script:", ex);	
				}
			}
		});
	}*/

	private void startActiveScanner(int index) {
		SequenceScript sequenceScript = getSelectedSequenceScript(index);
		SiteNode node = createTargetToScanSequence(sequenceScript, index);
		extensionSequence.setDirectScanScript(sequenceScript);
		extensionActiveScan.showCustomScanDialog(node);
		//showDialog(target);
	}

	private void showDialog(Target target){
		SequenceCustomScanDialog.showCustomScanDialog(extensionActiveScan, target);
	}

	private SiteNode createTargetToScanSequence(SequenceScript script, int index) {
		/*String name = Constant.messages.getString("zest.script.sequence.scanname", wrapper.getName());

		SiteNode fakeRoot = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);
		SiteNode fakeDirectory = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);*/

		HttpMessage msg = script.getAllRequestsInScript().get(index);
		return messageToSiteNode(msg, index);


		/*Target target = new SequenceTarget(new SequenceStructuralSiteNode(fakeRoot, name, uri), name);
		target.setRecurse(true);
		return target;*/
	}

	private SiteNode messageToSiteNode(HttpMessage msg, int messageIndex)
	{
		SiteNode temp = null;
		try {
			int messageNumber = messageIndex+1;
			String uri = getUrlDecodedUri(msg);
			String name = messageNumber + ": " + msg.getRequestHeader().getMethod() + " " + uri;

			SiteNode fakeRoot = new SiteNode(null, SEQUENCE_HISTORY_TYPE, "FakeRoot");
			temp = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);
			fakeRoot.add(temp);
			HistoryReference ref = new HistoryReference(extensionHistory.getModel().getSession(), SEQUENCE_HISTORY_TYPE, msg);
			extensionHistory.addHistory(ref);
			temp.setHistoryReference(ref);
		} catch(Exception e) {
			logger.error("An exception occurred while converting a HttpMessage to SiteNode: " + e.getMessage(), e);
		}
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

	private static class SequenceStructuralSiteNode extends StructuralSiteNode {

		private final String customName;
		private final URI customURI;
		private final SequenceStructuralSiteNode childNode;

		public SequenceStructuralSiteNode(SiteNode rootNode, String customName, URI customURI) {
			super(rootNode);
			this.customName = customName;
			this.customURI = customURI;
			this.childNode = new SequenceStructuralSiteNode((SiteNode) rootNode.getChildAt(0), customName, customURI, null);
		}

		private SequenceStructuralSiteNode(SiteNode node, String customName, URI customURI, Object dummy) {
			super(node);
			this.customName = customName;
			this.customURI = customURI;
			this.childNode = null;
		}

		@Override
		public String getName() {
			return customName;
		}

		@Override
		public URI getURI() {
			return customURI;
		}

		@Override
		public Iterator<StructuralNode> getChildIterator() {
			if (childNode != null) {
				return new SingleStructuralSiteNodeIterator(childNode);
			}
			return super.getChildIterator();
		}

		private static class SingleStructuralSiteNodeIterator implements Iterator<StructuralNode> {

			private final SequenceStructuralSiteNode node;
			private boolean exhausted;

			public SingleStructuralSiteNodeIterator(SequenceStructuralSiteNode node) {
				this.node = node;
			}

			@Override
			public boolean hasNext() {
				return !exhausted;
			}

			@Override
			public StructuralSiteNode next() {
				if (exhausted) {
					throw new NoSuchElementException("No more (fake) sequence nodes.");
				}
				exhausted = true;
				return node;
			}

			@Override
			public void remove() {
			}
		}
	}

	private static class SequenceTarget extends Target {

		private final String displayName;

		public SequenceTarget(StructuralSiteNode node, String displayName) {
			super(node);
			this.displayName = displayName;
		}

		@Override
		public String getDisplayName() {
			return displayName;
		}
	}
}

