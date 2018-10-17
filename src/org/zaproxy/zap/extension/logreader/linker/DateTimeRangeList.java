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

package org.zaproxy.zap.extension.logreader.linker;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DateTimeRangeList<T> {

    private ArrayList<DateTimeRangeWithValue<T>> list;

    public DateTimeRangeList() {
        this.list = new ArrayList<>();
    }

    public void add(LocalDateTime from, LocalDateTime till, T value){
        if(from == null) throw new IllegalArgumentException("from is null");
        if(till == null) throw new IllegalArgumentException("till is null");
        if(value == null) throw new IllegalArgumentException("value is null");
        list.add(new DateTimeRangeWithValue<>(from, till, value));
    }

    public List<T> getInsideRangeValues(LocalDateTime from, LocalDateTime till) {
        return getInsideRange(from, till).stream().map(i -> i.getValue()).collect(Collectors.toList());
    }

    public List<DateTimeRangeWithValue<T>> getInsideRange(LocalDateTime from, LocalDateTime till) {
        return list.stream().filter(i -> isInsideRange(i, from, till)).collect(Collectors.toList());
    }

    private boolean isInsideRange(DateTimeRangeWithValue<T> item, LocalDateTime from, LocalDateTime till) {
        return  item.getFrom().compareTo(from) >= 0 &&
                item.getTill().compareTo(from) >= 0 &&
                item.getFrom().compareTo(till) <= 0 &&
                item.getTill().compareTo(till) <= 0;
    }

    public List<T> getIntersectingRangeValues(LocalDateTime from, LocalDateTime till) {
        return getIntersectingRange(from, till).stream().map(i -> i.getValue()).collect(Collectors.toList());
    }

    public List<DateTimeRangeWithValue<T>> getIntersectingRange(LocalDateTime from, LocalDateTime till) {
        return list.stream().filter(i -> isIntersectingRange(i, from, till)).collect(Collectors.toList());
    }

    private boolean isIntersectingRange(DateTimeRangeWithValue<T> item, LocalDateTime from, LocalDateTime till) {
        return  (from.compareTo(item.getFrom()) >= 0 &&
                 from.compareTo(item.getTill()) <= 0)
                 ||
                (till.compareTo(item.getFrom()) >= 0 &&
                 till.compareTo(item.getTill()) <= 0)
                 ||
                (from.compareTo(item.getFrom()) <= 0 &&
                 till.compareTo(item.getTill()) >= 0);
    }

    public static class DateTimeRangeWithValue<T> {
        private LocalDateTime from;
        private LocalDateTime till;
        private T value;

        DateTimeRangeWithValue(LocalDateTime from, LocalDateTime till, T value) {
            this.from = from;
            this.till = till;
            this.value = value;
        }

        public LocalDateTime getFrom() {
            return from;
        }

        public LocalDateTime getTill() {
            return till;
        }

        public T getValue() {
            return value;
        }
    }
}