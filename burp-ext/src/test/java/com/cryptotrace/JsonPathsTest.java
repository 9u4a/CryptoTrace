package com.cryptotrace;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonPathsTest {
    @Test
    void parsesAndFormatsSameSubsetAsServer() {
        List<Object> p = JsonPaths.parse("$.a['b-c'][0].d");
        assertEquals(List.of("a", "b-c", 0, "d"), p);
        assertEquals("$.a.b-c[0].d", JsonPaths.format(p));
        assertEquals(List.of(), JsonPaths.parse("$"));
        assertThrows(IllegalArgumentException.class, () -> JsonPaths.parse("a.b"));
        assertThrows(IllegalArgumentException.class, () -> JsonPaths.parse("$..x"));
    }

    @Test
    void leavesUnderPrefixIncludingScalarPrefix() {
        JsonElement root = JsonParser.parseString("{\"data\":{\"id\":\"alice\",\"tags\":[1,true]},\"other\":\"x\"}");
        List<List<Object>> leaves = JsonPaths.leaves(root, List.of("data"));
        assertEquals(List.of(List.of("data", "id"), List.of("data", "tags", 0), List.of("data", "tags", 1)), leaves);
        assertEquals(List.of(List.of("other")), JsonPaths.leaves(root, List.of("other")));
    }

    @Test
    void setReplacesLeaf() {
        JsonElement root = JsonParser.parseString("{\"data\":{\"id\":\"alice\"}}");
        JsonPaths.set(root, List.of("data", "id"), new JsonPrimitive("<x>"));
        assertEquals("{\"data\":{\"id\":\"<x>\"}}", ServerClient.GSON.toJson(root));
    }
}
