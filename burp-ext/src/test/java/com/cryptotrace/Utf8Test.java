package com.cryptotrace;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Korean (non-Latin-1) text must survive the trip Burp message <-> crypto server in both directions. */
class Utf8Test {
    @Test
    void bodyTextIsUtf8Bytes() {
        String plain = "{\"name\":\"김민준\",\"msg\":\"이체 한도 변경 문의\"}";
        assertArrayEquals(plain.getBytes(StandardCharsets.UTF_8), Utf8.bytes(plain));
        assertEquals(plain, Utf8.text(plain.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void headerValuesRoundTripThroughBurpsOneCharPerByteStrings() {
        // Burp keeps header values as one char per byte: UTF-8 bytes of 한글 arrive as Latin-1 mojibake.
        String unicode = "평문 값 테스트";
        String burp = new String(unicode.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        assertEquals(unicode, Utf8.fromBurpHeader(burp), "Burp's header string -> real text for the server");
        assertEquals(burp, Utf8.toBurpHeader(unicode), "text from the server -> UTF-8 bytes in Burp's header string");
        // plain ASCII and genuine Latin-1 that isn't valid UTF-8 are left alone
        assertEquals("abc=1; x=2", Utf8.fromBurpHeader("abc=1; x=2"));
        assertEquals("café", Utf8.fromBurpHeader("café"));
        assertEquals("abc", Utf8.toBurpHeader("abc"));
    }
}
