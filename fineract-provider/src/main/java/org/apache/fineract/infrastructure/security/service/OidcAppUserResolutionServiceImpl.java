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
package org.apache.fineract.infrastructure.security.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.security.data.OidcIdentity;
import org.apache.fineract.infrastructure.security.exception.OidcUserNotFoundException;
import org.apache.fineract.organisation.office.domain.Office;
import org.apache.fineract.organisation.office.domain.OfficeRepository;
import org.apache.fineract.useradministration.domain.AppUser;
import org.apache.fineract.useradministration.domain.AppUserRepository;
import org.apache.fineract.useradministration.domain.Role;
import org.apache.fineract.useradministration.domain.RoleRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OidcAppUserResolutionServiceImpl implements OidcAppUserResolutionService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final OfficeRepository officeRepository;
    private final FineractProperties fineractProperties;

    // Stateless encoder — safe to create once per class
    private static final PasswordEncoder PASSWORD_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Override
    @Transactional
    public AppUser resolveOrCreate(OidcIdentity identity, Set<String> requestedRoles) {
        String issuer = identity.issuer();
        String subject = identity.subject();
        String username = identity.username();
        String email = identity.email();

        if (issuer == null || issuer.isBlank() || subject == null || subject.isBlank()) {
            log.warn("OIDC token for username '{}' lacks issuer or subject — refusing to resolve a Fineract user", username);
            throw new OidcUserNotFoundException(username);
        }

        // 1. Lookup by stable external identity (issuer, sub)
        AppUser user = appUserRepository.findByOidcIdentity(issuer, subject);
        if (user != null) {
            log.debug("OIDC user resolved by bound identity issuer='{}' subject='{}'", issuer, subject);
            return user;
        }

        // 2. First-login linking: only via an IdP-verified email, to an unbound, non-system account
        if (email != null && identity.emailVerified()) {
            user = appUserRepository.findActiveUserByEmail(email);
            if (user != null && !user.hasOidcIdentity() && !user.isSystemUser()) {
                user.bindOidcIdentity(issuer, subject);
                appUserRepository.saveAndFlush(user);
                log.info("Linked Fineract user '{}' to OIDC identity issuer='{}' subject='{}' via verified email", user.getUsername(),
                        issuer, subject);
                return user;
            }
            if (user != null) {
                log.warn("OIDC identity issuer='{}' subject='{}' matched existing user '{}' by email but linking is not permitted",
                        issuer, subject, user.getUsername());
            }
        }

        // 3. Auto-create when enabled
        FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties oidcConfig = fineractProperties.getSecurity()
                .getOidcFederation();

        if (!oidcConfig.isAutoCreateUser()) {
            log.warn("OIDC identity issuer='{}' subject='{}' (username '{}') not bound to any Fineract user and auto-create is disabled",
                    issuer, subject, username);
            throw new OidcUserNotFoundException(username);
        }

        if (appUserRepository.findAppUserByName(username) != null) {
            log.warn("Cannot auto-create OIDC user '{}': username already exists and is not bound to issuer='{}' subject='{}'", username,
                    issuer, subject);
            throw new OidcUserNotFoundException(username);
        }

        log.info("Auto-creating Fineract user for OIDC identity issuer='{}' subject='{}'", issuer, subject);
        return createUser(identity, requestedRoles, oidcConfig);
    }

    private AppUser createUser(OidcIdentity identity, Set<String> requestedRoles,
            FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties oidcConfig) {
        String username = identity.username();
        String email = identity.email();
        String firstName = identity.firstName();
        String lastName = identity.lastName();

        final Office headOffice = officeRepository.findById(fineractProperties.getDefaults().getOfficeId())
                .orElseThrow(() -> new IllegalStateException("Head office (id=1) not found — cannot auto-create OIDC user"));

        String encodedPassword = PASSWORD_ENCODER.encode(new RandomPasswordGenerator(20).generate());

        User springUser = new User(username, encodedPassword, true, true, true, true, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        Set<Role> roles = resolveRoles(oidcConfig.getDefaultRoles(), requestedRoles);

        String resolvedEmail = email != null ? email : username + "@oidc.placeholder";
        String resolvedFirstName = firstName != null ? firstName : username;
        String resolvedLastName = lastName != null ? lastName : "";

        AppUser appUser = new AppUser(headOffice, springUser, roles, resolvedEmail, resolvedFirstName, resolvedLastName, null, true, false);
        appUser.bindOidcIdentity(identity.issuer(), identity.subject());

        AppUser saved = appUserRepository.saveAndFlush(appUser);
        log.info("Auto-created Fineract user '{}' (id={}) from OIDC identity", username, saved.getId());
        return saved;
    }

    private Set<Role> resolveRoles(String defaultRolesConfig, Set<String> requestedRoles) {
        Set<Role> result = new HashSet<>();
        Stream.concat(Arrays.stream(defaultRolesConfig.split(",")), requestedRoles.stream()).map(String::trim)
                .filter(name -> !name.isEmpty()).forEach(name -> {
                    Role role = roleRepository.getRoleByName(name);
                    if (role != null) {
                        result.add(role);
                    } else {
                        log.warn("OIDC role mapping: role '{}' not found in Fineract — skipping", name);
                    }
                });
        return result;
    }
}
