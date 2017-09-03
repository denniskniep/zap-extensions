package org.zaproxy.zap.extension.sequence;

import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.network.HttpMessage;

public class SingleSequenceScannerHook implements ScannerHook {

    @Override
    public void scannerComplete() {

    }

    @Override
    public void beforeScan(HttpMessage httpMessage, AbstractPlugin abstractPlugin, Scanner scanner) {

    }

    @Override
    public void afterScan(HttpMessage httpMessage, AbstractPlugin abstractPlugin, Scanner scanner) {

    }
}
