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

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.extension.search.HttpSearcher;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.search.SearchResult;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class HistoryIdCustomSearch implements HttpSearcher {

    public static final String NAME = "HistoryId";
    public static final String SEPARATOR = ",";

    @Override
    public String getName() {
        return NAME;
    }

    private Integer tryParse(String value){
        try{
            return Integer.parseInt(value);
        }catch (NumberFormatException e){
            return null;
        }
    }

    private HttpMessage tryGetHttpMessage(int historyId){
        try{
            HistoryReference historyReference = new HistoryReference(historyId);
            return historyReference.getHttpMessage();
        }catch (HttpMalformedHeaderException | DatabaseException e){
            return null;
        }
    }

    @Override
    public List<SearchResult> search(Pattern pattern, boolean inverse) {
        List<SearchResult> results = new ArrayList<>();
        String filter = pattern.toString();
        String[] historyIds = filter.split(SEPARATOR);

        for (String historyIdValue : historyIds){

            Integer historyId = tryParse(historyIdValue);
            if(historyId == null){
                continue;
            }

            HttpMessage httpMessage = tryGetHttpMessage(historyId);
            if(httpMessage == null){
                continue;
            }

            SearchResult result = new SearchResult(ExtensionSearch.Type.Custom, NAME, filter, historyId.toString(), new SearchMatch(
                    httpMessage,
                    SearchMatch.Location.REQUEST_BODY,
                    0,
                    0));
            results.add(result);
        }

        return results;
    }

    @Override
    public List<SearchResult> search(Pattern pattern, boolean inverse, int maximumMatches) {
        return search(pattern, inverse);
    }
}
