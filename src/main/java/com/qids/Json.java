package com.qids;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, strict RFC 8259 JSON parser, so the SDK needs no dependencies.
 *
 * Objects become {@code Map<String, Object>} (insertion-ordered), arrays
 * {@code List<Object>}, strings {@code String}, integers {@code Long} (or
 * {@code Double} when they do not fit), other numbers {@code Double}, and
 * true / false / null {@code Boolean} / {@code null}.
 *
 * This replaced regular expressions that required fields in one exact order
 * and no others: an ETSI GS QKD 014 key object carrying the optional
 * key_ID_extension parsed to zero keys, silently.
 */
final class Json {

    /** Deeper nesting is refused rather than overflowing the stack. */
    static final int MAX_DEPTH = 256;

    private final String text;
    private int pos;
    private int depth;

    private Json(String text) {
        this.text = text;
    }

    /** Parse a complete JSON document. */
    static Object parse(String text) {
        if (text == null) throw new IllegalArgumentException("JSON input is null");
        Json parser = new Json(text);
        parser.skipWhitespace();
        Object value = parser.readValue();
        parser.skipWhitespace();
        if (parser.pos != text.length()) throw parser.error("trailing characters");
        return value;
    }

    /** Parse a document that must be a JSON object. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) throw new IllegalArgumentException("expected a JSON object");
        return (Map<String, Object>) value;
    }

    // -- typed accessors for response fields ---------------------------------

    static String string(Map<String, Object> obj, String key, String fallback) {
        Object v = obj.get(key);
        return v instanceof String ? (String) v : fallback;
    }

    static long number(Map<String, Object> obj, String key, long fallback) {
        Object v = obj.get(key);
        return v instanceof Number ? ((Number) v).longValue() : fallback;
    }

    /** True only for a JSON {@code true}; anything else, including absence, is false. */
    static boolean isTrue(Map<String, Object> obj, String key) {
        return Boolean.TRUE.equals(obj.get(key));
    }

    @SuppressWarnings("unchecked")
    static List<Object> array(Map<String, Object> obj, String key) {
        Object v = obj.get(key);
        return v instanceof List ? (List<Object>) v : new ArrayList<>();
    }

    // -- parser --------------------------------------------------------------

    private Object readValue() {
        if (pos >= text.length()) throw error("unexpected end of input");
        char c = text.charAt(pos);
        switch (c) {
            case '{': return readObject();
            case '[': return readArray();
            case '"': return readString();
            case 't': expectWord("true"); return Boolean.TRUE;
            case 'f': expectWord("false"); return Boolean.FALSE;
            case 'n': expectWord("null"); return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return readNumber();
                throw error("unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> readObject() {
        enter();
        Map<String, Object> obj = new LinkedHashMap<>();
        pos++; // {
        skipWhitespace();
        if (peek() == '}') { pos++; depth--; return obj; }
        while (true) {
            skipWhitespace();
            if (peek() != '"') throw error("expected a string key");
            String key = readString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            obj.put(key, readValue());
            skipWhitespace();
            char c = next();
            if (c == '}') { depth--; return obj; }
            if (c != ',') throw error("expected ',' or '}'");
        }
    }

    private List<Object> readArray() {
        enter();
        List<Object> list = new ArrayList<>();
        pos++; // [
        skipWhitespace();
        if (peek() == ']') { pos++; depth--; return list; }
        while (true) {
            skipWhitespace();
            list.add(readValue());
            skipWhitespace();
            char c = next();
            if (c == ']') { depth--; return list; }
            if (c != ',') throw error("expected ',' or ']'");
        }
    }

    private String readString() {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= text.length()) throw error("unterminated string");
            char c = text.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c < 0x20) throw error("unescaped control character in string");
            if (c != '\\') { sb.append(c); continue; }
            if (pos >= text.length()) throw error("unterminated escape");
            char e = text.charAt(pos++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (pos + 4 > text.length()) throw error("truncated \\u escape");
                    try {
                        sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw error("invalid \\u escape");
                    }
                    pos += 4;
                    break;
                default: throw error("invalid escape '\\" + e + "'");
            }
        }
    }

    private Object readNumber() {
        int start = pos;
        if (peek() == '-') pos++;
        if (peek() == '0') {
            pos++;
        } else if (Character.isDigit(peek())) {
            while (Character.isDigit(peek())) pos++;
        } else {
            throw error("invalid number");
        }
        boolean integral = true;
        if (peek() == '.') {
            integral = false;
            pos++;
            if (!Character.isDigit(peek())) throw error("invalid number");
            while (Character.isDigit(peek())) pos++;
        }
        if (peek() == 'e' || peek() == 'E') {
            integral = false;
            pos++;
            if (peek() == '+' || peek() == '-') pos++;
            if (!Character.isDigit(peek())) throw error("invalid number");
            while (Character.isDigit(peek())) pos++;
        }
        String literal = text.substring(start, pos);
        if (integral) {
            try {
                return Long.parseLong(literal);
            } catch (NumberFormatException tooBig) {
                return Double.parseDouble(literal);
            }
        }
        return Double.parseDouble(literal);
    }

    private void enter() {
        if (++depth > MAX_DEPTH) throw error("nested deeper than " + MAX_DEPTH);
    }

    private void expectWord(String word) {
        if (!text.startsWith(word, pos)) throw error("expected '" + word + "'");
        pos += word.length();
    }

    private void expect(char c) {
        if (next() != c) throw error("expected '" + c + "'");
    }

    private char next() {
        if (pos >= text.length()) throw error("unexpected end of input");
        return text.charAt(pos++);
    }

    private char peek() {
        return pos < text.length() ? text.charAt(pos) : '\0';
    }

    private void skipWhitespace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
            pos++;
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("invalid JSON at offset " + pos + ": " + message);
    }
}
