package org.zaproxy.zap.extension.sequence;

import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ascan.CustomScanDialog;
import org.zaproxy.zap.extension.ascan.CustomScanPanel;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.model.Target;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SequenceCustomScanDialog extends CustomScanDialog {

	private static final long serialVersionUID = 1L;

	public SequenceCustomScanDialog(ExtensionActiveScan extensionActiveScan, String[] strings, List<CustomScanPanel> list, Frame frame, Dimension dimension) {
		super(extensionActiveScan, strings, list, frame, dimension);
	}

	public static void showCustomScanDialog(ExtensionActiveScan extensionActiveScan, Target target){
			// Work out the tabs
			String[] tabs = CustomScanDialog.STD_TAB_LABELS;
			CustomScanDialog customScanDialog = new SequenceCustomScanDialog(extensionActiveScan, tabs, new ArrayList<CustomScanPanel>(),
					View.getSingleton().getMainFrame(), new Dimension(700, 500));

			if (target != null) {
				customScanDialog.init(target);
			} else {
				// Keep the previously selected target
				customScanDialog.init(null);
			}
			customScanDialog.setVisible(true);
		}
}
