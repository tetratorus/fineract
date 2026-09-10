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
package org.apache.fineract.template.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.template.data.TemplateData;
import org.apache.fineract.template.data.TemplateMapperData;
import org.apache.fineract.template.domain.TemplateFunctions;
import org.apache.fineract.template.exception.TemplateForbiddenException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
@ConditionalOnMissingBean(value = TemplateMergeService.class, ignored = TemplateMergeServiceImpl.class)
public class TemplateMergeServiceImpl implements TemplateMergeService {

    private final FineractProperties fineractProperties;

    @Override
    public String compile(final TemplateData template, final Map<String, Object> scopes) {
        scopes.put("static", TemplateFunctions.INSTANCE);

        var mf = new DefaultMustacheFactory();
        var mustache = mf.compile(Reader.of(template.getText()), template.getName());

        compiledMapFromMappers(asMap(template.getMappers()), scopes);

        expandMapArrays(scopes);

        var stringWriter = new StringWriter();
        mustache.execute(stringWriter, scopes);

        return stringWriter.toString();
    }

    private void compiledMapFromMappers(final Map<String, String> data, final Map<String, Object> scopes) {
        final MustacheFactory mf = new DefaultMustacheFactory();

        if (data != null) {
            for (final Map.Entry<String, String> entry : data.entrySet()) {
                final Mustache mappersMustache = mf.compile(Reader.of(entry.getValue()), "");
                final StringWriter stringWriter = new StringWriter();

                mappersMustache.execute(stringWriter, scopes);
                String url = stringWriter.toString();
                final String baseUri = String.valueOf(scopes.get("BASE_URI"));
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    url = baseUri + url;
                }
                try {
                    scopes.put(entry.getKey(), getMapFromUrl(url, baseUri));
                } catch (final IOException e) {
                    log.error("getCompiledMapFromMappers() failed", e);
                }
            }
        }
    }

    private LinkedHashMap<String, String> asMap(List<TemplateMapperData> mappers) {
        final LinkedHashMap<String, String> map = new LinkedHashMap<>();

        for (var mapper : mappers) {
            map.put(mapper.getMapperkey(), mapper.getMappervalue());
        }

        return map;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getMapFromUrl(final String url, final String baseUri) throws IOException {
        final HttpURLConnection connection = getConnection(url, baseUri);
        if (connection == null) {
            throw new IOException("Unable to open connection to template mapper url");
        }

        final String response = getStringFromInputStream(connection.getInputStream());
        HashMap<String, Object> result = new HashMap<>();
        if (connection.getContentType().equals("text/plain")) {
            result.put("src", response);
        } else {
            result = new ObjectMapper().readValue(response, HashMap.class);
        }
        return result;
    }

    private static String getStringFromInputStream(final InputStream is) {
        try {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (final IOException e) {
            log.error("getStringFromInputStream() failed", e);
            return "";
        }
    }

    private HttpURLConnection getConnection(final String url, final String baseUri) {
        final URI target = parseHttpUri(url);
        final boolean sameOrigin = isSameOrigin(target, baseUri);

        if (!sameOrigin) {
            if (!isWhitelisted(url)) {
                throw new TemplateForbiddenException(url);
            }
            if (resolvesToRestrictedAddress(target.getHost())) {
                throw new TemplateForbiddenException(url);
            }
        }

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) target.toURL().openConnection();
            connection.setInstanceFollowRedirects(false);
            if (sameOrigin) {
                final String authToken = ThreadLocalContextUtil.getAuthToken();
                if (authToken != null) {
                    connection.setRequestProperty("Authorization", "Basic " + authToken);// NOSONAR
                } else {
                    final String name = SecurityContextHolder.getContext().getAuthentication().getName();
                    final String password = SecurityContextHolder.getContext().getAuthentication().getCredentials().toString();
                    connection.setAuthenticator(new Authenticator() {

                        @Override
                        protected PasswordAuthentication getPasswordAuthentication() {
                            return new PasswordAuthentication(name, password.toCharArray());
                        }
                    });
                }
                TrustModifier.relaxHostChecking(connection);
            }

            connection.setDoInput(true);

        } catch (IOException | KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error("getConnection() failed, return null", e);
        }

        return connection;
    }

    private static URI parseHttpUri(final String url) {
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new TemplateForbiddenException(url);
        }
        final String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https")) || uri.getHost() == null
                || uri.getRawUserInfo() != null) {
            throw new TemplateForbiddenException(url);
        }
        return uri;
    }

    private static boolean isSameOrigin(final URI target, final String baseUri) {
        if (baseUri == null) {
            return false;
        }
        final URI base;
        try {
            base = new URI(baseUri);
        } catch (URISyntaxException e) {
            return false;
        }
        if (base.getScheme() == null || base.getHost() == null) {
            return false;
        }
        return base.getScheme().equalsIgnoreCase(target.getScheme()) && base.getHost().equalsIgnoreCase(target.getHost())
                && effectivePort(base) == effectivePort(target);
    }

    private static int effectivePort(final URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private boolean isWhitelisted(final String url) {
        if (fineractProperties.getTemplate() == null || fineractProperties.getTemplate().getRegexWhitelist() == null) {
            return false;
        }
        for (String urlPattern : fineractProperties.getTemplate().getRegexWhitelist()) {
            if (urlPattern == null || urlPattern.isBlank()) {
                continue;
            }
            Pattern pattern = Pattern.compile(urlPattern);
            Matcher matcher = pattern.matcher(url);
            if (matcher.matches()) {
                return true;
            }
        }
        return false;
    }

    private static boolean resolvesToRestrictedAddress(final String host) {
        final InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return true;
        }
        for (InetAddress address : addresses) {
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress() || isUniqueLocalIpv6(address)
                    || isCarrierGradeNat(address)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUniqueLocalIpv6(final InetAddress address) {
        final byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
    }

    private static boolean isCarrierGradeNat(final InetAddress address) {
        final byte[] bytes = address.getAddress();
        return bytes.length == 4 && (bytes[0] & 0xff) == 100 && (bytes[1] & 0xc0) == 64;
    }

    @SuppressWarnings("unchecked")
    private void expandMapArrays(Object value) {
        if (value instanceof Map) {
            Map<String, Object> valueAsMap = (Map<String, Object>) value;
            Map<String, Object> valueAsMapTemp = new HashMap<>();

            for (Map.Entry<String, Object> valueAsMapEntry : valueAsMap.entrySet()) {
                Object valueAsMapEntryValue = valueAsMapEntry.getValue();
                if (valueAsMapEntryValue instanceof Map) { // JSON Object
                    expandMapArrays(valueAsMapEntryValue);
                } else if (valueAsMapEntryValue instanceof Iterable) { // JSON
                    // Array
                    Iterable<Object> valueAsMapEntryValueIterable = (Iterable<Object>) valueAsMapEntryValue;
                    String valueAsMapEntryKey = valueAsMapEntry.getKey();
                    int i = 0;
                    for (Object object : valueAsMapEntryValueIterable) {
                        valueAsMapTemp.put(valueAsMapEntryKey + "#" + i, object);
                        ++i;
                        expandMapArrays(object);

                    }
                }

            }
            valueAsMap.putAll(valueAsMapTemp);

        }
    }
}
