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

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class DateTimeParser {

    public final static String DEFAULT_FORMATTER = "ISO_DATE_TIME";

    private final static Map<String, DateTimeFormatter> formatters = new HashMap<>();

    private static final String NO_OVERWRITE_ZONE_SPECIFIED = "";

    static{
        formatters.put(DEFAULT_FORMATTER, DateTimeFormatter.ISO_DATE_TIME);
        formatters.put("RFC_1123_DATE_TIME", DateTimeFormatter.RFC_1123_DATE_TIME);
    }

    public static LocalDateTime parseToUtc(String date, String pattern, String overwriteZone) {

        DateTimeParseResult result;

        result = tryParseAsZoned(date, pattern, NO_OVERWRITE_ZONE_SPECIFIED);
        if(!result.isZoneMissing()){
            return result.getDateTime();
        }

        result = tryParseAsZoned(date, pattern, overwriteZone);
        if(!result.isZoneMissing()){
            return result.getDateTime();
        }

        return parseAsLocal(date, pattern);
    }

    public static void testPattern(Object pattern) {
        DateTimeFormatter formatter = getDateTimeFormatterOfPattern(pattern.toString());
        ZonedDateTime.now().format(formatter);
    }

    public static Set<String> getPredefinedFormatters(){
        return formatters.keySet();
    }

    private static DateTimeParseResult tryParseAsZoned(String date, String pattern, String zone){
        try {
            LocalDateTime parsed = parseAsZoned(date, pattern, zone);
            return new DateTimeParseResult(false, parsed);
        }
        catch (DateTimeParseException e) {
            if(isZoneMissingException(e)) {
                return new DateTimeParseResult(true, null);
            }
            throw e;
        }
    }

    private static LocalDateTime parseAsZoned(String date, String pattern, String zone) {
        DateTimeFormatter formatter = getDateTimeFormatterOfPattern(pattern);

        if(zone != null && !zone.isEmpty()){
            formatter = formatter.withZone(ZoneId.of(zone));
        }

        ZonedDateTime parsed = ZonedDateTime.parse(date, formatter);
        ZonedDateTime utc = parsed.withZoneSameInstant(ZoneOffset.UTC);
        return utc.toLocalDateTime();
    }

    public static DateTimeFormatter getDateTimeFormatterOfPattern(String pattern) {
        DateTimeFormatter predefinedFormatter = formatters.get(pattern);
        if(predefinedFormatter != null){
            return predefinedFormatter;
        }
        return DateTimeFormatter.ofPattern(pattern);
    }

    private static LocalDateTime parseAsLocal(String date, String pattern) {
        DateTimeFormatter formatter = getDateTimeFormatterOfPattern(pattern);
        return LocalDateTime.parse(date, formatter);
    }

    private static boolean isZoneMissingException(DateTimeParseException e) {
        return e.getCause() != null && e.getCause().getCause() != null && e.getCause().getCause().getMessage().startsWith("Unable to obtain ZoneId");
    }

    private static class DateTimeParseResult{

        private boolean isZoneMissing;
        private LocalDateTime dateTime;

        public DateTimeParseResult(boolean isZoneMissing, LocalDateTime dateTime) {
            this.isZoneMissing = isZoneMissing;
            this.dateTime = dateTime;
        }

        public boolean isZoneMissing() {
            return isZoneMissing;
        }

        public LocalDateTime getDateTime() {
            return dateTime;
        }
    }
}
