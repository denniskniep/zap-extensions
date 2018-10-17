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


public class DateTimeRangeListIntersectsRangeTest {

    private List<DateTimeRangeList.DateTimeRangeWithValue<String>> testIntersectsRangeWithOneItem(LocalDateTime from, LocalDateTime till) {
        DateTimeRangeList<String> store = new DateTimeRangeList<>();
        LocalDateTime dateAFrom = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime dateATill = LocalDateTime.of(2018, 10, 05, 10, 20, 35);
        store.add(dateAFrom, dateATill, "Hello A");
        return store.getIntersectingRange(from, till);
    }

    /**
     * Value:            |______|
     * QueryRange :    |___|
     */
    @Test
    public void testInsideRange_FromIsOutOfScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 29);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 31);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:            |______|
     * QueryRange :           |___|
     */
    @Test
    public void testInsideRange_TillIsOutOfScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 31);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 36);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:                |______|
     * QueryRange :    |__|
     */
    @Test
    public void testInsideRange_FromAndTillAreBeforeScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 27);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 29);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(0));
    }

    /**
     * Value:         |______|
     * QueryRange :            |__|
     */
    @Test
    public void testInsideRange_FromAndTillAreAfterScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 36);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 38);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(0));
    }

    /**
     * Value:         |_______|
     * QueryRange :     |__|
     */
    @Test
    public void testInsideRange_FromAndTillAreInsideScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 32);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 33);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:         |_______|
     * QueryRange :   |_______|
     */
    @Test
    public void testInsideRange_FromAndTillAreMatchingExactlyScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 35);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:         |_______|
     * QueryRange : |___________|
     */
    @Test
    public void testInsideRange_FromAndTillAreWrappingScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 29);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 36);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:         |_______|
     * QueryRange :       |
     */
    @Test
    public void testInsideRange_FromAndTillAreEqualInsideScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 32);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 32);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:         |_______|
     * QueryRange :   |
     */
    @Test
    public void testInsideRange_FromAndTillAreEqualInsideAtBeginOfScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 30);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }

    /**
     * Value:         |_______|
     * QueryRange :           |
     */
    @Test
    public void testInsideRange_FromAndTillAreEqualInsideAtEndOfScope() {
        LocalDateTime from = LocalDateTime.of(2018, 10, 05, 10, 20, 35);
        LocalDateTime till = LocalDateTime.of(2018, 10, 05, 10, 20, 35);
        List<DateTimeRangeList.DateTimeRangeWithValue<String>> results = testIntersectsRangeWithOneItem(from, till);
        assertThat(results.size(), is(1));
    }
}

