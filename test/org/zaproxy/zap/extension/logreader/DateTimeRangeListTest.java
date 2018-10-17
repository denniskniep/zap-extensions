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

import org.junit.Test;
import org.zaproxy.zap.extension.logreader.linker.DateTimeRangeList;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class DateTimeRangeListTest {

    @Test
    public void testExactDates() {

        DateTimeRangeList<String> store = new DateTimeRangeList<>();

        LocalDateTime dateA1From = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime dateA1Till = LocalDateTime.of(2018, 10, 05, 10, 20, 30);

        LocalDateTime dateA2From = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime dateA2Till = LocalDateTime.of(2018, 10, 05, 10, 20, 30);

        LocalDateTime dateBFrom = LocalDateTime.of(2018, 10, 05, 11, 21, 31);
        LocalDateTime dateBTill = LocalDateTime.of(2018, 10, 05, 11, 21, 31);

        LocalDateTime dateCFrom = LocalDateTime.of(2018, 11, 05, 11, 20, 31);
        LocalDateTime dateCTill = LocalDateTime.of(2018, 11, 05, 11, 20, 31);

        LocalDateTime dateDFrom = LocalDateTime.of(2018, 11, 06, 11, 20, 31);
        LocalDateTime dateDTill = LocalDateTime.of(2018, 11, 06, 11, 20, 31);

        store.add(dateDFrom, dateDTill, "Hello D");
        store.add(dateA1From, dateA1Till, "Hello A1");
        store.add(dateA2From, dateA2Till, "Hello A2");
        store.add(dateCFrom, dateCTill, "Hello C");
        store.add(dateBFrom, dateBTill, "Hello B");

        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 30, 01);
        LocalDateTime till = LocalDateTime.of(2018, 11, 05, 12, 30, 01);

        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = store.getIntersectingRange(from, till);

        assertThat(results.get(0).getValue(), is("Hello C"));
        assertThat(results.get(1).getValue(), is("Hello B"));
    }

    @Test
    public void testDateRanges() {

        DateTimeRangeList<String> store = new DateTimeRangeList<>();

        LocalDateTime dateA1From = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime dateA1Till = LocalDateTime.of(2018, 10, 05, 10, 20, 32);

        LocalDateTime dateA2From = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime dateA2Till = LocalDateTime.of(2018, 10, 05, 10, 20, 32);

        LocalDateTime dateBFrom = LocalDateTime.of(2018, 10, 05, 11, 21, 31);
        LocalDateTime dateBTill = LocalDateTime.of(2018, 10, 05, 11, 21, 33);

        LocalDateTime dateCFrom = LocalDateTime.of(2018, 11, 05, 11, 20, 31);
        LocalDateTime dateCTill = LocalDateTime.of(2018, 11, 05, 11, 20, 33);

        LocalDateTime dateDFrom = LocalDateTime.of(2018, 11, 06, 11, 20, 31);
        LocalDateTime dateDTill = LocalDateTime.of(2018, 11, 06, 11, 20, 33);

        store.add(dateDFrom, dateDTill, "Hello D");
        store.add(dateA1From, dateA1Till, "Hello A1");
        store.add(dateA2From, dateA2Till, "Hello A2");
        store.add(dateCFrom, dateCTill, "Hello C");
        store.add(dateBFrom, dateBTill, "Hello B");

        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 30, 01);
        LocalDateTime till = LocalDateTime.of(2018, 11, 05, 12, 30, 01);

        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = store.getIntersectingRange(from, till);

        assertThat(results.get(0).getValue(), is("Hello C"));
        assertThat(results.get(1).getValue(), is("Hello B"));
    }
}
