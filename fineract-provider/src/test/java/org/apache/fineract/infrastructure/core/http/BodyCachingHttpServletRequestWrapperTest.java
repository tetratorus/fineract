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
package org.apache.fineract.infrastructure.core.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.ServletInputStream;
import java.nio.charset.StandardCharsets;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class BodyCachingHttpServletRequestWrapperTest {

    @Test
    void cachesBodyWithinLimit() throws Exception {
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/loans");
        request.setContent(body);

        BodyCachingHttpServletRequestWrapper wrapper = new BodyCachingHttpServletRequestWrapper(request, 1024);

        assertArrayEquals(body, wrapper.getInputStream().readAllBytes());
        wrapper.resetStream();
        assertArrayEquals(body, wrapper.getInputStream().readAllBytes());
    }

    @Test
    void rejectsBodyExceedingLimitWhileStreamingWithUnknownContentLength() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/loans") {

            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        request.setContent(new byte[2048]);

        assertThrows(RequestBodyTooLargeException.class, () -> new BodyCachingHttpServletRequestWrapper(request, 1024));
    }

    @Test
    void rejectsDeclaredContentLengthExceedingLimitWithoutReading() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/loans") {

            @Override
            public long getContentLengthLong() {
                return Long.MAX_VALUE;
            }

            @Override
            public ServletInputStream getInputStream() {
                throw new AssertionError("body must not be read when declared length exceeds the limit");
            }
        };

        assertThrows(RequestBodyTooLargeException.class, () -> new BodyCachingHttpServletRequestWrapper(request, 1024));
    }

    @Test
    void wrapReusesExistingWrapper() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/loans");
        request.setContent(new byte[10]);
        BodyCachingHttpServletRequestWrapper wrapper = new BodyCachingHttpServletRequestWrapper(request, 1024);

        assertSame(wrapper, BodyCachingHttpServletRequestWrapper.wrap(wrapper, 1));
    }

    @Test
    void tooLargeExceptionWritesPayloadTooLargeResponse() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        new RequestBodyTooLargeException(1024).toServletResponse(response);

        assertEquals(HttpStatus.SC_REQUEST_TOO_LONG, response.getStatus());
        assertEquals("application/json", response.getContentType());
    }
}
