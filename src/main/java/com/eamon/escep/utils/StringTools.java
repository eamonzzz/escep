package com.eamon.escep.utils;

import java.util.Collection;

/**
 * @author: eamon
 * @date: 2019-07-11 17:06
 * @description:
 */
public class StringTools {
    public static String getAsStringWithSeparator(final String separator, final Collection<?> values) {
        final StringBuilder names = new StringBuilder();
        for (final Object value : values) {
            if (names.length() != 0) {
                names.append(separator);
            }
            names.append(value);
        }
        return names.toString();
    }
}
