/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.sequence;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ExtensionSequence extends ExtensionAdaptor {

	private static final List<Class<?>> DEPENDENCIES;
	private final AutomaticSequenceScannerHook sequenceScannerHook;

	private ExtensionScript extScript;
	private ExtensionActiveScan extActiveScan;
	public static final Logger logger = Logger.getLogger(ExtensionSequence.class);
	public static final ImageIcon ICON = new ImageIcon(ExtensionSequence.class.getResource("/org/zaproxy/zap/extension/sequence/resources/icons/script-sequence.png"));
	public static final String TYPE_SEQUENCE = "sequence";

	static {
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionScript.class);
		DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

	private SequenceAscanPanel sequencePanel;

	private ScriptType scriptType;

	public ExtensionSequence() {
		super("ExtensionSequence");
		this.setOrder(29);
		sequenceScannerHook = new AutomaticSequenceScannerHook(getExtScript());
	}
	
	@Override
	public void initView(ViewDelegate view) {
		super.initView(view);

		ExtensionActiveScan extAscan = getExtActiveScan();
		if (extAscan != null) {
			sequencePanel = new SequenceAscanPanel(getExtScript());
		}
	}
	
	@Override
	public void postInit() {
		if (sequencePanel != null) {
			getExtActiveScan().addCustomScanPanel(sequencePanel);
		}
	}

	@Override
	public List<Class<?>> getDependencies() {
		return DEPENDENCIES;
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}
	
	@Override
	public void unload() {
		super.unload();
		if (sequencePanel != null) {
			getExtActiveScan().removeCustomScanPanel(sequencePanel);
		}
		getExtScript().removeScripType(scriptType);
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}


	@Override
	public void hook(ExtensionHook extensionhook) {
		super.hook(extensionhook);
		
		//Create a new sequence script type and register
		scriptType = new ScriptType(TYPE_SEQUENCE, "script.type.sequence", ICON, false, new String[] {"append"});
		getExtScript().registerScriptType(scriptType);

		if (getView() != null) {
			extensionhook.getHookMenu().addPopupMenuItem(new SequencePopupMenuItem(this, getExtScript()));
		}

		//Add class as a scannerhook (implements the scannerhook interface)
		extensionhook.addScannerHook(sequenceScannerHook);
	}

	public void setDirectScanScript(ScriptWrapper script) {
		sequenceScannerHook.setDirectScanScript(script);
	}

	private ExtensionScript getExtScript() {
		if(extScript == null) {
			extScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
		}
		return extScript;
	}

	private ExtensionActiveScan getExtActiveScan(){
		if(extActiveScan == null){
			extActiveScan = Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
		}
		return extActiveScan;
	}
}