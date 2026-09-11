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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import okhttp3.Dns;
import okhttp3.HttpUrl;
import org.apache.commons.lang3.StringUtils;
import org.apache.fineract.infrastructure.hooks.exception.WebHookUrlNotAllowedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Guards outbound hook requests against Server-Side Request Forgery. Only URLs using an allowed scheme and pointing at
 * a publicly routable host are accepted; loopback, private, link-local (including cloud metadata endpoints), multicast
 * and other reserved addresses are rejected. Hosts explicitly listed in {@code fineract.hooks.webhook.allowed-hosts}
 * bypass the address check so that operators can still target trusted internal services.
 */
@Component
public class WebHookUrlValidator {

    private final Set<String> allowedSchemes;
    private final boolean allowPrivateAddresses;
    private final Set<String> allowedHosts;

    public WebHookUrlValidator(@Value("${fineract.hooks.webhook.allowed-schemes:http,https}") final String allowedSchemes,
            @Value("${fineract.hooks.webhook.allow-private-addresses:false}") final boolean allowPrivateAddresses,
            @Value("${fineract.hooks.webhook.allowed-hosts:}") final String allowedHosts) {
        this.allowedSchemes = splitLowerCase(allowedSchemes);
        this.allowPrivateAddresses = allowPrivateAddresses;
        this.allowedHosts = splitLowerCase(allowedHosts);
    }

    private static Set<String> splitLowerCase(final String csv) {
        if (StringUtils.isBlank(csv)) {
            return Set.of();
        }
        return Arrays.stream(csv.split(",")).map(String::trim).filter(StringUtils::isNotEmpty).map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Validates the given URL and returns its parsed form.
     *
     * @throws WebHookUrlNotAllowedException
     *             if the URL is malformed, uses a disallowed scheme, or resolves to a disallowed address
     */
    public HttpUrl validate(final String url) {
        if (StringUtils.isBlank(url)) {
            throw new WebHookUrlNotAllowedException(String.valueOf(url), "URL must not be blank");
        }
        final HttpUrl httpUrl = HttpUrl.parse(url.trim());
        if (httpUrl == null) {
            throw new WebHookUrlNotAllowedException(url, "URL is malformed");
        }
        if (!allowedSchemes.contains(httpUrl.scheme().toLowerCase(Locale.ROOT))) {
            throw new WebHookUrlNotAllowedException(url, "scheme must be one of " + allowedSchemes);
        }
        if (StringUtils.isNotEmpty(httpUrl.username()) || StringUtils.isNotEmpty(httpUrl.password())) {
            throw new WebHookUrlNotAllowedException(url, "credentials in URL are not supported");
        }
        final String host = httpUrl.host();
        if (isAllowedHost(host)) {
            return httpUrl;
        }
        final InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new WebHookUrlNotAllowedException(url, "host cannot be resolved");
        }
        for (final InetAddress address : addresses) {
            checkAddress(host, address);
        }
        return httpUrl;
    }

    /**
     * A {@link Dns} for OkHttp that re-checks every resolved address at connection time, so that DNS rebinding and
     * redirects cannot steer a request towards a disallowed destination.
     */
    public Dns restrictedDns() {
        return hostname -> {
            final List<InetAddress> addresses = Dns.SYSTEM.lookup(hostname);
            if (!isAllowedHost(hostname)) {
                for (final InetAddress address : addresses) {
                    if (isDisallowedAddress(address)) {
                        throw new UnknownHostException("Webhook host " + hostname + " resolves to disallowed address " + address);
                    }
                }
            }
            return addresses;
        };
    }

    private boolean isAllowedHost(final String host) {
        return allowedHosts.contains(host.toLowerCase(Locale.ROOT));
    }

    private void checkAddress(final String host, final InetAddress address) {
        if (isDisallowedAddress(address)) {
            throw new WebHookUrlNotAllowedException(host, "host resolves to a non-public address");
        }
    }

    boolean isDisallowedAddress(final InetAddress address) {
        if (allowPrivateAddresses) {
            return false;
        }
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        if (address instanceof Inet4Address) {
            return isReservedIpv4(address.getAddress());
        }
        if (address instanceof Inet6Address) {
            final byte[] bytes = address.getAddress();
            // fc00::/7 unique local addresses
            if ((bytes[0] & 0xfe) == 0xfc) {
                return true;
            }
            // 64:ff9b::/96 NAT64 and ::ffff:0:0/96 IPv4-mapped (the latter is normally already an Inet4Address)
            if (isNat64(bytes) || isIpv4Mapped(bytes)) {
                return isReservedIpv4(Arrays.copyOfRange(bytes, 12, 16)) || isPrivateIpv4(Arrays.copyOfRange(bytes, 12, 16));
            }
        }
        return false;
    }

    private static boolean isNat64(final byte[] b) {
        return b[0] == 0x00 && b[1] == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b && b[4] == 0 && b[5] == 0 && b[6] == 0
                && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0;
    }

    private static boolean isIpv4Mapped(final byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff;
    }

    private static boolean isPrivateIpv4(final byte[] b) {
        final int b0 = b[0] & 0xff;
        final int b1 = b[1] & 0xff;
        return b0 == 10 || b0 == 127 || (b0 == 172 && (b1 & 0xf0) == 16) || (b0 == 192 && b1 == 168) || (b0 == 169 && b1 == 254);
    }

    private static boolean isReservedIpv4(final byte[] b) {
        final int b0 = b[0] & 0xff;
        final int b1 = b[1] & 0xff;
        return b0 == 0 // 0.0.0.0/8 "this" network
                || (b0 == 100 && (b1 & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT
                || (b0 == 192 && b1 == 0 && (b[2] & 0xff) == 0) // 192.0.0.0/24 IETF protocol assignments
                || (b0 == 198 && (b1 & 0xfe) == 18) // 198.18.0.0/15 benchmarking
                || b0 >= 240; // 240.0.0.0/4 reserved and broadcast
    }
}
