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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class WebHookUrlValidatorTest {

    private final WebHookUrlValidator validator = new WebHookUrlValidator(null, false);

    @ParameterizedTest
    @ValueSource(strings = { "http://127.0.0.1/", "http://localhost:9200/", "http://10.0.0.1/", "http://172.16.5.5/",
            "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/", "http://100.64.0.1/", "http://0.0.0.0/",
            "http://[::1]/", "http://[fd00::1]/", "http://[::ffff:10.0.0.1]/" })
    public void rejectsNonPublicDestinations(String url) {
        assertThrows(IllegalArgumentException.class, () -> validator.validate(url));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "not a url", "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/",
            "http://user:pass@example.com/" })
    public void rejectsMalformedOrNonHttpUrls(String url) {
        assertThrows(IllegalArgumentException.class, () -> validator.validate(url));
    }

    @Test
    public void allowsPrivateDestinationsWhenExplicitlyEnabled() {
        new WebHookUrlValidator(null, true).validate("http://127.0.0.1:9200/");
    }

    @Test
    public void enforcesAllowedHosts() {
        assertThrows(IllegalArgumentException.class,
                () -> new WebHookUrlValidator("hooks.example.com", true).validate("http://127.0.0.1/"));
        assertThrows(IllegalArgumentException.class,
                () -> new WebHookUrlValidator("hooks.example.com", true).validate("http://evil.hooks.example.com/"));
    }

    @Test
    public void allowedHostSuffixMatching() throws UnknownHostException {
        WebHookUrlValidator allowlisted = new WebHookUrlValidator(".trusted.example.org", true);
        assertThrows(UnknownHostException.class, () -> allowlisted.lookup("localhost"));
        assertThrows(UnknownHostException.class, () -> allowlisted.lookup("nottrusted.example.org"));
    }

    @Test
    public void dnsLookupRejectsNonPublicAddresses() {
        assertThrows(UnknownHostException.class, () -> validator.lookup("localhost"));
    }

    @Test
    public void publiclyRoutableClassification() throws UnknownHostException {
        assertTrue(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("8.8.8.8")));
        assertTrue(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("2001:4860:4860::8888")));
        assertFalse(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("198.18.0.1")));
        assertFalse(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("192.0.0.1")));
        assertFalse(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("240.0.0.1")));
        assertFalse(WebHookUrlValidator.isPubliclyRoutable(InetAddress.getByName("::ffff:127.0.0.1")));
    }
}
