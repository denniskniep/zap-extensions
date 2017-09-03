package org.zaproxy.zap.extension.sequence;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.text.MessageFormat;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

public class SequencePopupMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	
	private final ExtensionScript extensionScript;
	public static final Logger logger = Logger.getLogger(SequencePopupMenuItem.class);
	private ExtensionSequence extensionSequence = null;
	

	public SequencePopupMenuItem(ExtensionSequence extensionSequence, ExtensionScript extensionScript) {
		super();
		this.extensionSequence = extensionSequence;
		this.extensionScript = extensionScript;
		initialize();
	}
	
	private void initialize() {
		this.setText(extensionSequence.getMessages().getString("sequence.popupmenuitem.activeScanSequence"));
		
		this.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					ScriptWrapper wrapper = (ScriptWrapper)extensionScript.getScriptUI().getSelectedNode().getUserObject();
					SequenceScript scr = extensionScript.getInterface(wrapper, SequenceScript.class);
					if (scr != null) {
						extensionSequence.setDirectScanScript(wrapper);
						scr.scanSequence();
						

					} else {
						String msg = extensionSequence.getMessages().getString("sequence.popupmenuitem.script.error.interface");
						View.getSingleton().showMessageDialog(MessageFormat.format(msg, wrapper.getName()));
					}
				} catch(Exception ex) {
					logger.warn("An exception occurred while starting an active scan for a sequence script:", ex);	
				}
			}
		});
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
