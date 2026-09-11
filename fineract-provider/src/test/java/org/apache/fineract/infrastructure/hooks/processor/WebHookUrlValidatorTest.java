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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.core.config.FineractProperties.FineractHooksProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WebHookUrlValidatorTest {

    private WebHookUrlValidator validator(final FineractHooksProperties hooks) {
        final FineractProperties properties = new FineractProperties();
        properties.setHooks(hooks);
        return new WebHookUrlValidator(properties);
    }

    private WebHookUrlValidator defaultValidator() {
        return validator(new FineractHooksProperties());
    }

    @ParameterizedTest
    @ValueSource(strings = { "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/", "http://localhost/", "http://10.0.0.5/",
            "http://172.16.0.1/", "http://192.168.1.1/", "http://0.0.0.0/", "http://[::1]/", "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/",
            "http://100.64.0.1/" })
    void rejectsNonPublicDestinationsByDefault(final String url) {
        assertThrows(WebHookUrlNotAllowedException.class, () -> defaultValidator().validate(url));
    }

    @ParameterizedTest
    @ValueSource(strings = { "ftp://8.8.8.8/", "file:///etc/passwd", "not a url", "", "http://user:pass@8.8.8.8/" })
    void rejectsUnsupportedSchemesAndMalformedUrls(final String url) {
        assertThrows(WebHookUrlNotAllowedException.class, () -> defaultValidator().validate(url));
    }

    @Test
    void acceptsPublicIpDestination() {
        assertDoesNotThrow(() -> defaultValidator().validate("https://8.8.8.8/hook"));
    }

    @Test
    void allowsPrivateNetworksWhenConfigured() {
        final FineractHooksProperties hooks = new FineractHooksProperties();
        hooks.setAllowPrivateNetworks(true);
        assertDoesNotThrow(() -> validator(hooks).validate("http://127.0.0.1:8080/"));
    }

    @Test
    void rejectsPlainHttpWhenInsecureHttpDisabled() {
        final FineractHooksProperties hooks = new FineractHooksProperties();
        hooks.setAllowInsecureHttp(false);
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator(hooks).validate("http://8.8.8.8/"));
        assertDoesNotThrow(() -> validator(hooks).validate("https://8.8.8.8/"));
    }

    @Test
    void enforcesHostAllowlist() {
        final FineractHooksProperties hooks = new FineractHooksProperties();
        hooks.setAllowPrivateNetworks(true);
        hooks.setAllowedHosts(List.of("hooks.example.com", "*.internal.example.org"));
        final WebHookUrlValidator validator = validator(hooks);
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate("http://127.0.0.1/"));
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate("http://8.8.8.8/"));
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate("http://internal.example.org/"));
        assertThrows(UnknownHostException.class, () -> validator.dns().lookup("evil.example.com"));
    }

    @Test
    void dnsRejectsNonPublicResolution() {
        assertThrows(UnknownHostException.class, () -> defaultValidator().dns().lookup("localhost"));
    }

    @Test
    void classifiesAddresses() throws UnknownHostException {
        assertTrue(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("8.8.8.8")));
        assertTrue(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("2001:4860:4860::8888")));
        assertFalse(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("169.254.169.254")));
        assertFalse(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("198.18.0.1")));
        assertFalse(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("224.0.0.1")));
        assertFalse(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("::ffff:10.0.0.1")));
        assertFalse(WebHookUrlValidator.isPublicAddress(InetAddress.getByName("fe80::1")));
    }
}
