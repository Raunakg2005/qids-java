package com.qids;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * A non-200 response from the QIDS gateway, with the fields of its JSON
 * error body. 401, 403 and 429 are thrown as the subclasses
 * {@link Unauthorized}, {@link Forbidden} and {@link RateLimited}.
 *
 * It extends {@link IOException}, so code that caught the IOException
 * earlier releases threw keeps working.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QIDSException extends IOException {
    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String error;
    private final String gatewayMessage;
    private final String reason;
    private final String requiredPermission;
    private final Duration retryAfter;
    private final String body;

    QIDSException(String op, int statusCode, String error, String gatewayMessage, String reason,
                  String requiredPermission, Duration retryAfter, String body) {
        super(describe(op, statusCode, error, gatewayMessage, reason, retryAfter));
        this.statusCode = statusCode;
        this.error = error;
        this.gatewayMessage = gatewayMessage;
        this.reason = reason;
        this.requiredPermission = requiredPermission;
        this.retryAfter = retryAfter;
        this.body = body;
    }

    /** The HTTP status code. */
    public int getStatusCode() { return statusCode; }

    /** The body's "error" field, e.g. "Rate limit exceeded"; empty when absent. */
    public String getError() { return error; }

    /** The body's "message" (or "detail") field; empty when absent. */
    public String getGatewayMessage() { return gatewayMessage; }

    /** The body's "reason" field; empty when absent. */
    public String getReason() { return reason; }

    /** On a 403, the permission the key's role lacks; empty when not given. */
    public String getRequiredPermission() { return requiredPermission; }

    /**
     * How long to wait before retrying: the body's retry_after_seconds, else
     * the Retry-After header. Empty when the gateway gave neither.
     */
    public Optional<Duration> getRetryAfter() { return Optional.ofNullable(retryAfter); }

    /** The raw response body. */
    public String getBody() { return body; }

    /** 401: the API key is missing or invalid. */
    public static class Unauthorized extends QIDSException {
        private static final long serialVersionUID = 1L;

        Unauthorized(String op, int status, String error, String message, String reason,
                     String permission, Duration retryAfter, String body) {
            super(op, status, error, message, reason, permission, retryAfter, body);
        }
    }

    /** 403: the API key's role lacks the permission; see {@link #getRequiredPermission()}. */
    public static class Forbidden extends QIDSException {
        private static final long serialVersionUID = 1L;

        Forbidden(String op, int status, String error, String message, String reason,
                  String permission, Duration retryAfter, String body) {
            super(op, status, error, message, reason, permission, retryAfter, body);
        }
    }

    /** 429: rate limited; see {@link #getRetryAfter()}. */
    public static class RateLimited extends QIDSException {
        private static final long serialVersionUID = 1L;

        RateLimited(String op, int status, String error, String message, String reason,
                    String permission, Duration retryAfter, String body) {
            super(op, status, error, message, reason, permission, retryAfter, body);
        }
    }

    /** Build the exception for a non-200 gateway response. */
    static QIDSException fromResponse(String op, HttpResponse<String> response) {
        String body = response.body() == null ? "" : response.body();
        Map<String, Object> obj = Map.of();
        try {
            obj = Json.parseObject(body);
        } catch (IllegalArgumentException ignored) {
            // Not a JSON object (a proxy's HTML page, say): keep the raw body.
        }
        String error = Json.string(obj, "error", "");
        String message = Json.string(obj, "message", Json.string(obj, "detail", ""));
        String reason = Json.string(obj, "reason", "");
        String permission = Json.string(obj, "required_permission", "");

        Duration retryAfter = null;
        double seconds = Json.decimal(obj, "retry_after_seconds", 0.0);
        if (seconds > 0) {
            retryAfter = Duration.ofMillis((long) (seconds * 1000));
        } else {
            Optional<String> header = response.headers().firstValue("Retry-After");
            if (header.isPresent()) {
                try {
                    long s = Long.parseLong(header.get().trim());
                    if (s > 0) retryAfter = Duration.ofSeconds(s);
                } catch (NumberFormatException ignored) {
                    // An HTTP-date Retry-After; the gateway sends seconds.
                }
            }
        }

        int status = response.statusCode();
        switch (status) {
            case 401: return new Unauthorized(op, status, error, message, reason, permission, retryAfter, body);
            case 403: return new Forbidden(op, status, error, message, reason, permission, retryAfter, body);
            case 429: return new RateLimited(op, status, error, message, reason, permission, retryAfter, body);
            default: return new QIDSException(op, status, error, message, reason, permission, retryAfter, body);
        }
    }

    private static String describe(String op, int status, String error, String message, String reason,
                                   Duration retryAfter) {
        StringBuilder sb = new StringBuilder("QIDS ").append(op).append(" returned HTTP ").append(status);
        for (String s : new String[] {error, message, reason}) {
            if (s != null && !s.isEmpty()) sb.append(": ").append(s);
        }
        if (retryAfter != null) sb.append(" (retry after ").append(retryAfter.toSeconds()).append(" s)");
        return sb.toString();
    }
}
