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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.fineract.infrastructure.hooks.exception.WebHookUrlNotAllowedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WebHookUrlValidatorTest {

    private final WebHookUrlValidator validator = new WebHookUrlValidator("http,https", false, "");

    @ParameterizedTest
    @ValueSource(strings = { "http://127.0.0.1/", "http://localhost:8080/hook", "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/", "http://172.16.3.4/", "http://192.168.1.1/", "http://0.0.0.0/", "http://100.64.0.1/", "http://[::1]/",
            "http://[fd00::1]/", "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/", "http://[64:ff9b::7f00:1]/", "http://224.0.0.1/",
            "http://255.255.255.255/" })
    void rejectsNonPublicAddresses(String url) {
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate(url));
    }

    @ParameterizedTest
    @ValueSource(strings = { "ftp://93.184.216.34/", "file:///etc/passwd", "gopher://93.184.216.34/", "not a url", "", "   " })
    void rejectsMalformedUrlsAndDisallowedSchemes(String url) {
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate(url));
    }

    @Test
    void rejectsCredentialsInUrl() {
        assertThrows(WebHookUrlNotAllowedException.class, () -> validator.validate("http://user:pass@93.184.216.34/"));
    }

    @Test
    void acceptsPublicAddress() {
        assertEquals("93.184.216.34", validator.validate("https://93.184.216.34/hook").host());
    }

    @Test
    void allowedHostBypassesAddressCheck() {
        WebHookUrlValidator withAllowList = new WebHookUrlValidator("http,https", false, "localhost, elastic.internal");
        assertDoesNotThrow(() -> withAllowList.validate("http://localhost:9200/"));
        assertDoesNotThrow(() -> withAllowList.validate("http://LOCALHOST:9200/"));
        assertThrows(WebHookUrlNotAllowedException.class, () -> withAllowList.validate("http://127.0.0.1:9200/"));
    }

    @Test
    void allowPrivateAddressesDisablesAddressCheckOnly() {
        WebHookUrlValidator permissive = new WebHookUrlValidator("https", true, "");
        assertDoesNotThrow(() -> permissive.validate("https://127.0.0.1/"));
        assertThrows(WebHookUrlNotAllowedException.class, () -> permissive.validate("http://127.0.0.1/"));
    }

    @Test
    void restrictedDnsRejectsNonPublicResolution() {
        assertThrows(UnknownHostException.class, () -> validator.restrictedDns().lookup("localhost"));
        assertThrows(UnknownHostException.class, () -> validator.restrictedDns().lookup("169.254.169.254"));
        assertDoesNotThrow(() -> validator.restrictedDns().lookup("93.184.216.34"));
    }

    @Test
    void classifiesAddresses() throws UnknownHostException {
        assertTrue(validator.isDisallowedAddress(InetAddress.getByName("198.18.0.1")));
        assertTrue(validator.isDisallowedAddress(InetAddress.getByName("192.0.0.1")));
        assertTrue(validator.isDisallowedAddress(InetAddress.getByName("240.0.0.1")));
        assertFalse(validator.isDisallowedAddress(InetAddress.getByName("8.8.8.8")));
        assertFalse(validator.isDisallowedAddress(InetAddress.getByName("2001:4860:4860::8888")));
    }
}
