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
import java.util.List;
import java.util.Locale;
import okhttp3.Dns;
import okhttp3.HttpUrl;
import org.apache.commons.lang3.StringUtils;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.core.config.FineractProperties.FineractHooksProperties;
import org.springframework.stereotype.Component;

/**
 * Restricts the destinations that outbound webhook requests may be sent to, in order to prevent server-side request
 * forgery (SSRF). Only {@code http}/{@code https} URLs are accepted, the destination host may be limited to a
 * configured allowlist, and unless explicitly enabled, hosts resolving to loopback, private, link-local, multicast or
 * other non-public addresses are rejected. Address checks are also applied at connection time through
 * {@link #dns()} so that DNS rebinding after validation cannot bypass them.
 */
@Component
public class WebHookUrlValidator {

    private final FineractHooksProperties properties;

    public WebHookUrlValidator(final FineractProperties fineractProperties) {
        final FineractHooksProperties hooks = fineractProperties.getHooks();
        this.properties = hooks != null ? hooks : new FineractHooksProperties();
    }

    public HttpUrl validate(final String url) {
        if (StringUtils.isBlank(url)) {
            throw new WebHookUrlNotAllowedException(String.valueOf(url), "url is empty");
        }
        final HttpUrl parsed = HttpUrl.parse(url);
        if (parsed == null) {
            throw new WebHookUrlNotAllowedException(url, "url is malformed or does not use http/https");
        }
        if (!parsed.isHttps() && !properties.isAllowInsecureHttp()) {
            throw new WebHookUrlNotAllowedException(url, "only https urls are permitted");
        }
        if (!parsed.username().isEmpty() || !parsed.password().isEmpty()) {
            throw new WebHookUrlNotAllowedException(url, "credentials in url are not permitted");
        }
        final String host = parsed.host().toLowerCase(Locale.ROOT);
        if (!isHostAllowed(host)) {
            throw new WebHookUrlNotAllowedException(url, "host is not in the configured allowlist");
        }
        if (!properties.isAllowPrivateNetworks()) {
            for (final InetAddress address : resolve(host)) {
                if (!isPublicAddress(address)) {
                    throw new WebHookUrlNotAllowedException(url, "host resolves to a non-public address " + address.getHostAddress());
                }
            }
        }
        return parsed;
    }

    /**
     * A {@link Dns} for OkHttp that re-applies the address restrictions on every lookup performed by the client, so that
     * the addresses actually connected to are the ones that were checked.
     */
    public Dns dns() {
        return hostname -> {
            if (!isHostAllowed(hostname.toLowerCase(Locale.ROOT))) {
                throw new UnknownHostException("Webhook host " + hostname + " is not in the configured allowlist");
            }
            final List<InetAddress> addresses = Dns.SYSTEM.lookup(hostname);
            if (!properties.isAllowPrivateNetworks()) {
                for (final InetAddress address : addresses) {
                    if (!isPublicAddress(address)) {
                        throw new UnknownHostException(
                                "Webhook host " + hostname + " resolves to non-public address " + address.getHostAddress());
                    }
                }
            }
            return addresses;
        };
    }

    private List<InetAddress> resolve(final String host) {
        try {
            return Dns.SYSTEM.lookup(host);
        } catch (UnknownHostException e) {
            throw new WebHookUrlNotAllowedException(host, "host cannot be resolved");
        }
    }

    private boolean isHostAllowed(final String host) {
        final List<String> allowedHosts = properties.getAllowedHosts();
        if (allowedHosts == null || allowedHosts.stream().allMatch(StringUtils::isBlank)) {
            return true;
        }
        for (final String allowed : allowedHosts) {
            if (StringUtils.isBlank(allowed)) {
                continue;
            }
            final String pattern = allowed.trim().toLowerCase(Locale.ROOT);
            if (pattern.startsWith("*.")) {
                final String suffix = pattern.substring(1);
                if (host.endsWith(suffix) && host.length() > suffix.length()) {
                    return true;
                }
            } else if (pattern.equals(host)) {
                return true;
            }
        }
        return false;
    }

    static boolean isPublicAddress(final InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        final byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            return isPublicIpv4(bytes);
        }
        if (address instanceof Inet6Address) {
            // IPv4-mapped (::ffff:a.b.c.d)
            if (isIpv4Mapped(bytes)) {
                return isPublicIpv4(new byte[] { bytes[12], bytes[13], bytes[14], bytes[15] });
            }
            final int first = bytes[0] & 0xff;
            // fc00::/7 unique local
            if ((first & 0xfe) == 0xfc) {
                return false;
            }
            // 64:ff9b::/96 NAT64, 2002::/16 6to4 and ::/128 handled above; 100::/64 discard-only
            if (first == 0x01 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0
                    && bytes[7] == 0) {
                return false;
            }
            return true;
        }
        return false;
    }

    private static boolean isIpv4Mapped(final byte[] bytes) {
        if (bytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return (bytes[10] & 0xff) == 0xff && (bytes[11] & 0xff) == 0xff;
    }

    private static boolean isPublicIpv4(final byte[] b) {
        final int b0 = b[0] & 0xff;
        final int b1 = b[1] & 0xff;
        final int b2 = b[2] & 0xff;
        if (b0 == 0 || b0 == 10 || b0 == 127) {
            return false;
        }
        if (b0 == 100 && b1 >= 64 && b1 <= 127) { // 100.64.0.0/10 shared address space
            return false;
        }
        if (b0 == 169 && b1 == 254) { // link-local incl. cloud metadata 169.254.169.254
            return false;
        }
        if (b0 == 172 && b1 >= 16 && b1 <= 31) {
            return false;
        }
        if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) { // 192.0.0.0/24, 192.0.2.0/24
            return false;
        }
        if (b0 == 192 && b1 == 168) {
            return false;
        }
        if (b0 == 198 && (b1 == 18 || b1 == 19)) { // 198.18.0.0/15 benchmarking
            return false;
        }
        if (b0 == 198 && b1 == 51 && b2 == 100) { // 198.51.100.0/24
            return false;
        }
        if (b0 == 203 && b1 == 0 && b2 == 113) { // 203.0.113.0/24
            return false;
        }
        if (b0 >= 224) { // multicast and reserved incl. broadcast
            return false;
        }
        return true;
    }
}
