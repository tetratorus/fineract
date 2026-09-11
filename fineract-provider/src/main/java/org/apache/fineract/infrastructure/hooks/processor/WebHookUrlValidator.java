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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import okhttp3.Dns;
import okhttp3.HttpUrl;

/**
 * Guards outbound hook (webhook) requests against SSRF. Hook URLs are stored configuration supplied through the API,
 * so they are treated as untrusted: only http/https URLs without credentials are accepted, hosts must resolve to
 * publicly routable addresses, and an optional host allowlist can be enforced.
 *
 * <ul>
 * <li>{@code fineract.hooks.allowedHosts}: comma separated list of host names. A leading dot allows all subdomains
 * (e.g. {@code .example.com}). When empty, every public host is allowed.</li>
 * <li>{@code fineract.hooks.allowPrivateAddresses}: set to {@code true} to permit loopback, private and link-local
 * destinations (development only).</li>
 * </ul>
 */
public final class WebHookUrlValidator implements Dns {

    static final String ALLOWED_HOSTS_PROPERTY = "fineract.hooks.allowedHosts";
    static final String ALLOW_PRIVATE_ADDRESSES_PROPERTY = "fineract.hooks.allowPrivateAddresses";

    private final List<String> allowedHosts;
    private final boolean allowPrivateAddresses;

    public WebHookUrlValidator() {
        this(System.getProperty(ALLOWED_HOSTS_PROPERTY, System.getenv("FINERACT_HOOKS_ALLOWED_HOSTS")),
                Boolean.parseBoolean(System.getProperty(ALLOW_PRIVATE_ADDRESSES_PROPERTY,
                        System.getenv("FINERACT_HOOKS_ALLOW_PRIVATE_ADDRESSES"))));
    }

    WebHookUrlValidator(final String allowedHostsCsv, final boolean allowPrivateAddresses) {
        this.allowedHosts = parseHosts(allowedHostsCsv);
        this.allowPrivateAddresses = allowPrivateAddresses;
    }

    private static List<String> parseHosts(final String csv) {
        final List<String> hosts = new ArrayList<>();
        if (csv == null) {
            return hosts;
        }
        for (final String entry : csv.split(",")) {
            final String host = entry.trim().toLowerCase(Locale.ROOT);
            if (!host.isEmpty()) {
                hosts.add(host);
            }
        }
        return hosts;
    }

    /**
     * Validates the URL syntactically and resolves its host, rejecting anything that is not a plain http/https URL
     * pointing at an allowed, publicly routable host.
     *
     * @return the parsed URL
     * @throws IllegalArgumentException
     *             if the URL must not be contacted
     */
    public HttpUrl validate(final String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Hook URL must not be empty");
        }
        final HttpUrl httpUrl = HttpUrl.parse(url);
        if (httpUrl == null) {
            throw new IllegalArgumentException("Hook URL is not a valid http(s) URL");
        }
        if (!httpUrl.username().isEmpty() || !httpUrl.password().isEmpty()) {
            throw new IllegalArgumentException("Hook URL must not contain credentials");
        }
        final String host = httpUrl.host().toLowerCase(Locale.ROOT);
        if (!isHostAllowed(host)) {
            throw new IllegalArgumentException("Hook URL host is not in the allowed hosts list");
        }
        try {
            checkAddresses(host, Arrays.asList(InetAddress.getAllByName(host)));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Hook URL host cannot be resolved", e);
        }
        return httpUrl;
    }

    private boolean isHostAllowed(final String host) {
        if (allowedHosts.isEmpty()) {
            return true;
        }
        for (final String allowed : allowedHosts) {
            if (allowed.startsWith(".")) {
                if (host.endsWith(allowed) || host.equals(allowed.substring(1))) {
                    return true;
                }
            } else if (host.equals(allowed)) {
                return true;
            }
        }
        return false;
    }

    private void checkAddresses(final String host, final List<InetAddress> addresses) throws UnknownHostException {
        if (addresses.isEmpty()) {
            throw new UnknownHostException(host);
        }
        if (allowPrivateAddresses) {
            return;
        }
        for (final InetAddress address : addresses) {
            if (!isPubliclyRoutable(address)) {
                throw new IllegalArgumentException("Hook URL host resolves to a non-public address");
            }
        }
    }

    static boolean isPubliclyRoutable(final InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return false;
        }
        final byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            final int first = raw[0] & 0xff;
            final int second = raw[1] & 0xff;
            // 0.0.0.0/8, 100.64.0.0/10 (shared address space), 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4
            if (first == 0 || first >= 240) {
                return false;
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return false;
            }
            if (first == 192 && second == 0 && raw[2] == 0) {
                return false;
            }
            return !(first == 198 && (second == 18 || second == 19));
        }
        if (address instanceof Inet6Address) {
            final int first = raw[0] & 0xff;
            // fc00::/7 unique local addresses
            if ((first & 0xfe) == 0xfc) {
                return false;
            }
            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible addresses
            boolean leadingZero = true;
            for (int i = 0; i < 10; i++) {
                if (raw[i] != 0) {
                    leadingZero = false;
                    break;
                }
            }
            if (leadingZero) {
                try {
                    return isPubliclyRoutable(InetAddress.getByAddress(Arrays.copyOfRange(raw, 12, 16)));
                } catch (UnknownHostException e) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * OkHttp {@link Dns} hook: re-validates the addresses actually used for the connection so that DNS rebinding
     * between validation and dispatch cannot redirect the request to an internal host.
     */
    @Override
    public List<InetAddress> lookup(final String hostname) throws UnknownHostException {
        final List<InetAddress> addresses = Dns.SYSTEM.lookup(hostname);
        final String host = hostname.toLowerCase(Locale.ROOT);
        if (!isHostAllowed(host)) {
            throw new UnknownHostException("Hook URL host is not in the allowed hosts list: " + hostname);
        }
        try {
            checkAddresses(host, addresses);
        } catch (IllegalArgumentException e) {
            throw new UnknownHostException(e.getMessage() + ": " + hostname);
        }
        return addresses;
    }
}
