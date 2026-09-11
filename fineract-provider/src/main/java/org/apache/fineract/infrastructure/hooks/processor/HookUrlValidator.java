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
import java.util.List;
import okhttp3.Dns;
import okhttp3.HttpUrl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Guards outbound hook requests against SSRF: only http(s) URLs without credentials are accepted, and unless
 * {@code fineract.hooks.allow-private-networks} is enabled, hosts that resolve to loopback, link-local, site-local,
 * multicast, wildcard or otherwise non-public addresses are rejected. The same policy is applied to every address
 * returned by DNS at connect time (see {@link #dns()}) so that DNS rebinding cannot bypass the create-time check.
 */
@Component
public class HookUrlValidator {

    private final boolean allowPrivateNetworks;

    public HookUrlValidator(@Value("${fineract.hooks.allow-private-networks:false}") final boolean allowPrivateNetworks) {
        this.allowPrivateNetworks = allowPrivateNetworks;
    }

    public HttpUrl validate(final String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Hook URL must not be empty");
        }
        final HttpUrl httpUrl = HttpUrl.parse(url);
        if (httpUrl == null) {
            throw new IllegalArgumentException("Hook URL is not a valid http(s) URL");
        }
        if (!httpUrl.scheme().equals("http") && !httpUrl.scheme().equals("https")) {
            throw new IllegalArgumentException("Hook URL scheme must be http or https");
        }
        if (!httpUrl.username().isEmpty() || !httpUrl.password().isEmpty()) {
            throw new IllegalArgumentException("Hook URL must not contain credentials");
        }
        try {
            checkAddresses(httpUrl.host(), InetAddress.getAllByName(httpUrl.host()));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Hook URL host could not be resolved: " + httpUrl.host(), e);
        }
        return httpUrl;
    }

    public Dns dns() {
        return hostname -> {
            final InetAddress[] addresses = InetAddress.getAllByName(hostname);
            try {
                checkAddresses(hostname, addresses);
            } catch (IllegalArgumentException e) {
                throw new UnknownHostException(e.getMessage());
            }
            final List<InetAddress> result = new ArrayList<>(addresses.length);
            for (final InetAddress address : addresses) {
                result.add(address);
            }
            return result;
        };
    }

    private void checkAddresses(final String host, final InetAddress[] addresses) {
        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("Hook URL host could not be resolved: " + host);
        }
        if (allowPrivateNetworks) {
            return;
        }
        for (final InetAddress address : addresses) {
            if (!isPublic(address)) {
                throw new IllegalArgumentException("Hook URL host resolves to a non-public address: " + host);
            }
        }
    }

    static boolean isPublic(final InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        final byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            final int first = bytes[0] & 0xFF;
            final int second = bytes[1] & 0xFF;
            // 100.64.0.0/10 shared address space (carrier NAT)
            if (first == 100 && second >= 64 && second <= 127) {
                return false;
            }
            // 192.0.0.0/24 IETF protocol assignments
            if (first == 192 && second == 0 && bytes[2] == 0) {
                return false;
            }
            // 198.18.0.0/15 benchmarking
            if (first == 198 && (second == 18 || second == 19)) {
                return false;
            }
            // 240.0.0.0/4 reserved and broadcast
            return first < 240;
        }
        if (address instanceof Inet6Address) {
            final int first = bytes[0] & 0xFF;
            // fc00::/7 unique local
            if ((first & 0xFE) == 0xFC) {
                return false;
            }
            // 2002::/16 6to4: check the embedded IPv4 address
            if (first == 0x20 && (bytes[1] & 0xFF) == 0x02) {
                return isPublicEmbeddedIpv4(bytes, 2);
            }
            // 64:ff9b::/96 NAT64: check the embedded IPv4 address
            if (first == 0x00 && (bytes[1] & 0xFF) == 0x64 && (bytes[2] & 0xFF) == 0xFF && (bytes[3] & 0xFF) == 0x9B) {
                return isPublicEmbeddedIpv4(bytes, 12);
            }
        }
        return true;
    }

    private static boolean isPublicEmbeddedIpv4(final byte[] bytes, final int offset) {
        try {
            return isPublic(InetAddress.getByAddress(new byte[] { bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3] }));
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
