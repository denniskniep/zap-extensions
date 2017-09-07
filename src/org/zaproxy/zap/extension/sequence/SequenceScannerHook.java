package org.zaproxy.zap.extension.sequence;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ActiveScanTableModel;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptCollection;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

import javax.script.ScriptException;
import java.awt.*;
import java.io.IOException;
import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class SequenceScannerHook implements ScannerHook {

    private SequenceScript directSequenceScript = null;
    private ExtensionScript extensionScript;
    public static final Logger logger = Logger.getLogger(SequenceScannerHook.class);
    private final Pattern bracketsReplacePattern = Pattern.compile("(%7B%7B)(.*?)(%7D%7D)", Pattern.DOTALL);

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
        try
        {
            //If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the Scanner,
            //then the message has a specific Sequence script to scan.
            SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

            //If any script was found, send all the requests prior to the message to be scanned.
            if(seqScr!= null) {
                UnescapeVarBracketsForReplacement(msg);
                HttpMessage newMsg = seqScr.runSequenceBefore(msg, plugin);
                updateMessage(msg, newMsg);
                addHistoryReferenceToMessageIfNotExists(msg);
            }
        }catch (Exception ex){
            logger.error("Error in beforeScan of SequenceScannerHook", ex);
        }
    }

    @Override
    public void afterScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        try
        {
            //If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the Scanner,
            //then the message has a specific Sequence script to scan.
            SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

            //If any script was found, send all the requests after the message that was scanned.
            if(seqScr!= null) {
                HttpSender httpSender = plugin.getParent().getHttpSender();
                HttpRedirectFollower.followRedirections(msg, HttpRedirectFollower.getHttpRequestConfig(plugin), httpSender);
                removeMessageFromActiveScanPanelInEdt(msg, scanner);
                overwriteHistoryReferenceInMessage(msg);
                addMessageToActiveScanPanel(plugin, msg);
                seqScr.runSequenceAfter(msg, plugin);
            }

        }catch (Exception ex){
            logger.error("Error in afterScan of SequenceScannerHook", ex);
        }
    }

    private void removeMessageFromActiveScanPanelInEdt(HttpMessage msg, Scanner scanner) {
        if(scanner instanceof ActiveScan && msg.getHistoryRef() != null) {
            final ActiveScan activeScan = (ActiveScan)scanner;
            final ActiveScanTableModel tableModel = activeScan.getMessagesTableModel();
            final int historyId = msg.getHistoryRef().getHistoryId();

            EventQueue.invokeLater(new Runnable() {
                @Override
                public void run() {
                    //activeScan.getMessagesIds().remove(historyId);
                    tableModel.removeEntry(historyId);
                }
            });
        }
    }

    private void addHistoryReferenceToMessageIfNotExists(HttpMessage msg) throws DatabaseException, HttpMalformedHeaderException {
        HistoryReference hRef = msg.getHistoryRef();
        if (hRef == null) {
            overwriteHistoryReferenceInMessage(msg);
        }
    }

    private void overwriteHistoryReferenceInMessage(HttpMessage msg) throws DatabaseException, HttpMalformedHeaderException {
        new HistoryReference(
                Model.getSingleton().getSession(),
                HistoryReference.TYPE_SCANNER_TEMPORARY,
                msg);
    }

    private void addMessageToActiveScanPanel(AbstractPlugin plugin, HttpMessage msg) {
        plugin.getParent().notifyNewMessage(msg);
    }

    //ToDo: Maybe useful also for the IndexBasedZestRunner?
    private void UnescapeVarBracketsForReplacement(HttpMessage msg) throws HttpMalformedHeaderException {
        String replacedHeader = replaceBrackets(msg.getRequestHeader().toString());
        String replacedBody = replaceBrackets(msg.getRequestBody().toString());
        msg.setRequestHeader(replacedHeader);
        msg.setRequestBody(replacedBody);
    }

    private String replaceBrackets(String content) {
        return bracketsReplacePattern.matcher(content).replaceAll("{{$2}}");
    }

    public void setDirectScanScript(SequenceScript script) {
        directSequenceScript = script;
    }

    private SequenceScript getIncludedSequenceScript(HttpMessage msg, Scanner scanner) throws ScriptException, IOException {
        if (hasDirectSequenceScript()) {
            return directSequenceScript;
        }

        List<ScriptWrapper> sequences = getSequenceScripts(scanner);
        return findMatchingSequenceScriptForHttpMessage(sequences, msg);
    }

    private SequenceScript findMatchingSequenceScriptForHttpMessage(List<ScriptWrapper> sequences, HttpMessage msg) throws ScriptException, IOException {
        for(ScriptWrapper wrapper: sequences) {
            SequenceScript seqScr = extensionScript.getInterface(wrapper, SequenceScript.class);
            if (seqScr != null) {
                if (seqScr.isPartOfSequence(msg)) {
                    return seqScr;
                }
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

    private boolean hasDirectSequenceScript(){
        return directSequenceScript != null;
    }

    private void updateMessage(HttpMessage msg, HttpMessage newMsg) {
        msg.setRequestHeader(newMsg.getRequestHeader());
        msg.setRequestBody(newMsg.getRequestBody());
        msg.setCookies(new ArrayList<HttpCookie>()); // TODO: Check this please!
    }
}
