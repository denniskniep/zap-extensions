package org.zaproxy.zap.extension.sequence;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptCollection;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SequenceScannerHook implements ScannerHook {

    private SequenceScript directSequenceScript = null;
    private ExtensionScript extensionScript;
    public static final Logger logger = Logger.getLogger(SequenceScannerHook.class);

    public SequenceScannerHook(ExtensionScript extensionScript) {
        this.extensionScript = extensionScript;
    }

    @Override
    public void scannerComplete() {
        //Reset the sequence extension
        this.directSequenceScript = null;
    }

    @Override
    public void beforeScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        //If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the Scanner,
        //then the message has a specific Sequence script to scan.
        SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

        //If any script was found, send all the requests prior to the message to be scanned.
        if(seqScr!= null) {
            HttpMessage newMsg = seqScr.runSequenceBefore(msg, plugin);
            updateMessage(msg, newMsg);
        }
    }

    @Override
    public void afterScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        //If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the Scanner,
        //then the message has a specific Sequence script to scan.
        SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

        //If any script was found, send all the requests after the message that was scanned.
        if(seqScr!= null) {
            seqScr.runSequenceAfter(msg, plugin);
        }
    }

    public void setDirectScanScript(SequenceScript script) {
        directSequenceScript = script;
    }

    private SequenceScript getIncludedSequenceScript(HttpMessage msg, Scanner scanner) {
        if (hasDirectSeqeunceScript()) {
            return directSequenceScript;
        }

        List<ScriptWrapper> sequences = getSequenceScripts(scanner);
        return findMatchingSequenceScriptForHttpMessage(sequences, msg);
    }

    private SequenceScript findMatchingSequenceScriptForHttpMessage(List<ScriptWrapper> sequences, HttpMessage msg) {
        for(ScriptWrapper wrapper: sequences) {
            try {
                SequenceScript seqScr = extensionScript.getInterface(wrapper, SequenceScript.class);
                if (seqScr != null) {
                    if (seqScr.isPartOfSequence(msg)) {
                        return seqScr;
                    }
                }
            } catch (Exception e) {
                logger.debug("Exception occurred, while trying to fetch Included Sequence Script: " + e.getMessage());
            }
        }
        return null;
    }

    private List<ScriptWrapper> getSequenceScripts(Scanner scanner) {
        Set<ScriptCollection> scs = scanner.getScriptCollections();
        if (scs != null) {
            for (ScriptCollection sc : scs) {
                if (sc.getType().getName().equals(ExtensionSequence.TYPE_SEQUENCE)) {
                    return sc.getScripts();
                }
            }
        }

        return new ArrayList<>();
    }

    private boolean hasDirectSeqeunceScript(){
        return directSequenceScript != null;
    }

    private void updateMessage(HttpMessage msg, HttpMessage newMsg) {
        msg.setRequestHeader(newMsg.getRequestHeader());
        msg.setRequestBody(newMsg.getRequestBody());
        msg.setCookies(new ArrayList<HttpCookie>()); // TODO: Check this please!
    }
}
