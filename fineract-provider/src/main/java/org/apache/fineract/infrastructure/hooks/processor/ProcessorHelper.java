/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.infrastructure.hooks.processor;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.OkHttpClient;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.hooks.exception.HookUrlForbiddenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

@Service
public final class ProcessorHelper {

    // Nota bene: Similar code to insecure HTTPS is also in Fineract Client's
    // org.apache.fineract.client.util.FineractClient.Builder.insecure()

    private static final Logger LOG = LoggerFactory.getLogger(ProcessorHelper.class);

    @SuppressWarnings("unused")
    private static final X509TrustManager insecureX509TrustManager = new X509TrustManager() {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}// NOSONAR

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}// NOSONAR

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[] {};
        }
    };

    /**
     * Configure HTTP client to be "insecure", as in skipping host SSL certificate verification. While this can be
     * useful during development e.g. when using self-signed certificates, it should never be enabled in production (due
     * to "man in the middle").
     */
    private final boolean insecureHttpClient = Boolean.getBoolean("fineract.insecureHttpClient");
    private final SSLContext insecureSSLContext;
    private final FineractProperties fineractProperties;

    public ProcessorHelper(final FineractProperties fineractProperties) throws KeyManagementException, NoSuchAlgorithmException {
        this.fineractProperties = fineractProperties;
        if (insecureHttpClient) {
            insecureSSLContext = createInsecureSSLContext();
        } else {
            insecureSSLContext = null;
        }
    }

    private OkHttpClient createClient() {
        var okBuilder = new OkHttpClient.Builder();
        if (insecureHttpClient) {
            configureInsecureClient(okBuilder);
        }
        return okBuilder.build();
    }

    private void configureInsecureClient(final OkHttpClient.Builder okBuilder) {
        okBuilder.sslSocketFactory(insecureSSLContext.getSocketFactory(), insecureX509TrustManager);
        HostnameVerifier insecureHostnameVerifier = (hostname, session) -> true;// NOSONAR
        okBuilder.hostnameVerifier(insecureHostnameVerifier);
    }

    private SSLContext createInsecureSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext insecureSSLContext = SSLContext.getInstance("TLS"); // TODO "TLS" or "SSL" as in
        // FineractClient.Builder?
        insecureSSLContext.init(null, new TrustManager[] { insecureX509TrustManager }, new SecureRandom());
        return insecureSSLContext;
    }

    @SuppressWarnings("rawtypes")
    public Callback createCallback(final String url) {
        return new Callback() {

            @Override
            public void onResponse(@SuppressWarnings("unused") Call call, retrofit2.Response response) {
                LOG.debug("URL: {} - Status: {}", url, response.code());
            }

            @Override
            public void onFailure(@SuppressWarnings("unused") Call call, Throwable t) {
                LOG.error("URL: {} - Retrofit failure occurred", url, t);
            }
        };
    }

    public WebHookService createWebHookService(final String url) {
        validateUrl(url);
        final OkHttpClient client = createClient();
        final Retrofit.Builder retrofitBuilder = new Retrofit.Builder();
        retrofitBuilder.baseUrl(url);
        retrofitBuilder.client(client);
        retrofitBuilder.addConverterFactory(GsonConverterFactory.create());
        final Retrofit retrofit = retrofitBuilder.build();
        return retrofit.create(WebHookService.class);
    }

    private void validateUrl(final String url) {
        if (url == null) {
            throw new HookUrlForbiddenException(url);
        }
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new HookUrlForbiddenException(url, e);
        }
        final String scheme = uri.getScheme();
        if (scheme == null || uri.getHost() == null) {
            throw new HookUrlForbiddenException(url);
        }
        final String lowerScheme = scheme.toLowerCase(Locale.ROOT);
        if (!"http".equals(lowerScheme) && !"https".equals(lowerScheme)) {
            throw new HookUrlForbiddenException(url);
        }
        if (uri.getRawUserInfo() != null) {
            throw new HookUrlForbiddenException(url);
        }

        final FineractProperties.FineractHooksProperties hooks = fineractProperties.getHooks();
        if (hooks == null || !hooks.isRegexWhitelistEnabled()) {
            return;
        }
        final List<String> whitelist = hooks.getRegexWhitelist();
        if (whitelist != null) {
            for (final String urlPattern : whitelist) {
                if (Pattern.compile(urlPattern).matcher(url).matches()) {
                    return;
                }
            }
        }
        throw new HookUrlForbiddenException(url);
    }

    @SuppressWarnings("rawtypes")
    public Callback createCallback(final String url, String payload) {

        return new Callback() {

            @Override
            public void onResponse(@SuppressWarnings("unused") Call call, retrofit2.Response response) {
                LOG.debug("URL: {} - Status: {}", url, response.code());
            }

            @Override
            public void onFailure(@SuppressWarnings("unused") Call call, Throwable t) {
                LOG.error("URL: {} - Retrofit failure occurred", url, t);
            }
        };
    }
}
