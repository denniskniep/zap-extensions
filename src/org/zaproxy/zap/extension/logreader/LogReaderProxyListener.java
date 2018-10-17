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

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;

import java.util.Map;

public class LogReaderProxyListener implements OverrideMessageProxyListener {

    private static final Logger LOGGER = Logger.getLogger(LogReaderProxyListener.class);
    private ApplicationLogManager applicationLogManager;

    public LogReaderProxyListener(ApplicationLogManager applicationLogManager) {
        this.applicationLogManager = applicationLogManager;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        Map<String, Object> logMessageProperties = convertJsonToMap(msg);
        if(logMessageProperties != null){
            applicationLogManager.add(logMessageProperties);
        }
        respondWithHttpOk(msg);
        return true;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> convertJsonToMap(HttpMessage msg){
        try {
            JSONObject json = (JSONObject)JSONSerializer.toJSON(msg.getRequestBody().toString());
            return (Map<String, Object>) JSONObject.toBean(json, Map.class);
        } catch (Exception e) {
            LOGGER.error("Error during converting application log received via http message body from json to map: " + e.getMessage(), e);
            return null;
        }
    }

    private void respondWithHttpOk(HttpMessage msg) {
        HttpResponseHeader responseHeader = new HttpResponseHeader();
        responseHeader.setStatusCode(HttpStatusCode.OK);
        responseHeader.setContentLength(0);
        msg.setResponseHeader(responseHeader);
    }

    @Override
    public boolean onHttpResponseReceived(HttpMessage msg) {
        return true;
    }
}