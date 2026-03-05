package me.stiglio.authManager.utils;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public final class MessageUtils {
    private MessageUtils() {
    }

    public static String colorizeAmpersand(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        StringBuilder out = new StringBuilder(text.length());
        for (int index = 0; index < text.length(); index++) {
            char current = text.charAt(index);
            if (current == '&' && index + 1 < text.length() && isLegacyColorCode(text.charAt(index + 1))) {
                out.append('\u00A7');
                continue;
            }
            out.append(current);
        }
        return out.toString();
    }

    public static Component toComponent(String legacyText) {
        return LegacyComponentSerializer.legacySection().deserialize(colorizeAmpersand(legacyText));
    }

    private static boolean isLegacyColorCode(char value) {
        return (value >= '0' && value <= '9')
                || (value >= 'a' && value <= 'f')
                || (value >= 'A' && value <= 'F')
                || (value >= 'k' && value <= 'o')
                || (value >= 'K' && value <= 'O')
                || value == 'r'
                || value == 'R'
                || value == 'x'
                || value == 'X';
    }
}
