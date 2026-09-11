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
package org.apache.fineract.infrastructure.security.data;

/**
 * Identity attributes extracted from an external OIDC token. {@code issuer} and {@code subject} form the stable identity
 * key; {@code username} and {@code email} are display / provisioning attributes and must not be used on their own to
 * select an existing Fineract account.
 */
public record OidcIdentity(String issuer, String subject, String username, String email, boolean emailVerified, String firstName,
        String lastName) {}
