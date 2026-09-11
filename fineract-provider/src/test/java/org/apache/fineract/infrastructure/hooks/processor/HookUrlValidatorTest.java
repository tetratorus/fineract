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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HookUrlValidatorTest {

    private final HookUrlValidator strict = new HookUrlValidator(false);
    private final HookUrlValidator permissive = new HookUrlValidator(true);

    @ParameterizedTest
    @ValueSource(strings = { "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://10.0.0.1/", "http://172.16.5.4/",
            "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/", "http://0.0.0.0/", "http://100.64.0.1/",
            "http://[fd00::1]/", "http://[fe80::1]/", "http://[::ffff:10.0.0.1]/" })
    public void rejectsNonPublicAddresses(final String url) {
        assertThrows(IllegalArgumentException.class, () -> strict.validate(url));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "http://user:pw@8.8.8.8/",
            "not a url" })
    public void rejectsUnsupportedSchemesAndCredentials(final String url) {
        assertThrows(IllegalArgumentException.class, () -> strict.validate(url));
        assertThrows(IllegalArgumentException.class, () -> permissive.validate(url));
    }

    @Test
    public void acceptsPublicAddress() {
        assertEquals("8.8.8.8", strict.validate("https://8.8.8.8/hooks/").host());
    }

    @Test
    public void permissiveModeAcceptsPrivateAddresses() {
        assertEquals("127.0.0.1", permissive.validate("http://127.0.0.1:8080/").host());
    }

    @Test
    public void dnsRejectsNonPublicResolution() {
        assertThrows(UnknownHostException.class, () -> strict.dns().lookup("localhost"));
        assertFalse(permissive.dns().lookup("localhost").isEmpty());
    }

    @Test
    public void classifiesAddresses() throws UnknownHostException {
        assertTrue(HookUrlValidator.isPublic(InetAddress.getByName("93.184.216.34")));
        assertTrue(HookUrlValidator.isPublic(InetAddress.getByName("2606:4700::1111")));
        assertFalse(HookUrlValidator.isPublic(InetAddress.getByName("198.18.0.1")));
        assertFalse(HookUrlValidator.isPublic(InetAddress.getByName("240.0.0.1")));
        assertFalse(HookUrlValidator.isPublic(InetAddress.getByName("255.255.255.255")));
        assertFalse(HookUrlValidator.isPublic(InetAddress.getByName("2002:7f00:1::")));
        assertFalse(HookUrlValidator.isPublic(InetAddress.getByName("64:ff9b::a00:1")));
    }
}
