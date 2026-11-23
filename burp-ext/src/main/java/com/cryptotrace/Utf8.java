package com.cryptotrace;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Text <-> bytes for Burp messages. Montoya's String overloads (withBody(String), bodyToString(), header values)
 * treat a String as one char per byte (Latin-1), which breaks Korean and any other non-Latin-1 text. Bodies are
 * always converted as UTF-8 bytes here; header values are mapped between Burp's byte-per-char strings and text.
 */
final class Utf8 {
    private Utf8() {}

    static byte[] bytes(String text) {
        return text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
    }

    static String text(byte[] raw) {
        return raw == null ? "" : new String(raw, StandardCharsets.UTF_8);
    }

    /** A header value as Burp holds it (one char per byte) -> the text it encodes, when those bytes are UTF-8. */
    static String fromBurpHeader(String burp) {
        if (burp == null) return null;
        boolean high = false;
        for (int i = 0; i < burp.length(); i++) {
            char c = burp.charAt(i);
            if (c > 0xff) return burp; // already real text
            if (c > 0x7f) high = true;
        }
        if (!high) return burp;
        byte[] raw = burp.getBytes(StandardCharsets.ISO_8859_1);
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            return burp; // genuine Latin-1, keep it
        }
    }

    /** Text for a header -> Burp's one-char-per-byte string of its UTF-8 bytes (ASCII stays as is). */
    static String toBurpHeader(String text) {
        if (text == null) return null;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 0x7f) return new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        }
        return text;
    }
}
