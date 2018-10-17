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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class DateTimeParserTest {

    private static final DateTimeFormatter TEST_FORMATTER = DateTimeFormatter.ISO_DATE_TIME;

    @Test
    public void testZoneIsInValue() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416+02:00",
                "yyyy-MM-dd'T'HH:mm:ss.SSS[XXX]",
                "");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T15:17:24.416"));
    }

    @Test
    public void testZoneIsNotSpecified() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416",
                "yyyy-MM-dd'T'HH:mm:ss.SSS[XXX]",
                "");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T17:17:24.416"));
    }

    @Test
    public void testZoneIsSpecified() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416",
                "yyyy-MM-dd'T'HH:mm:ss.SSS[XXX]",
                "UTC+8");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T09:17:24.416"));
    }

    @Test
    public void testZoneIsSpecifiedAndZoneInValue() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416+02:00",
                "yyyy-MM-dd'T'HH:mm:ss.SSS[XXX]",
                "UTC+8");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T15:17:24.416"));
    }

    @Test
    public void testPredefinedFormatters() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416+02:00",
                DateTimeParser.DEFAULT_FORMATTER,
                "UTC+8");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T15:17:24.416"));
    }

    @Test
    public void testZoneIsNotSpecifiedWithPredefinedFormatters() {
        LocalDateTime localDateTime = DateTimeParser.parseToUtc(
                "2018-10-11T17:17:24.416",
                DateTimeParser.DEFAULT_FORMATTER,
                "");

        assertThat(localDateTime.format(TEST_FORMATTER), is("2018-10-11T17:17:24.416"));
    }
}