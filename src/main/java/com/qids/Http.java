package com.qids;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * One HTTP exchange within one deadline, body included.
 *
 * {@link HttpRequest.Builder#timeout} stops at the response headers: a server
 * that sends its headers and then stalls held {@code HttpClient.send} for
 * ever. Here the whole exchange must finish within {@code timeout}, or the
 * request is cancelled and {@link HttpTimeoutException} is thrown.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
final class Http {
    private Http() {}

    static HttpResponse<String> send(HttpClient client, HttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<String>> future =
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        try {
            return future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new HttpTimeoutException("no complete answer from " + request.uri() + " within " + timeout);
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) throw (IOException) cause;
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            throw new IOException(cause);
        }
    }
}
