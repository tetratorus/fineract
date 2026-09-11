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
package org.apache.fineract.infrastructure.security.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.core.domain.FineractPlatformTenant;
import org.apache.fineract.infrastructure.core.domain.TenantOidcConfig;
import org.apache.fineract.infrastructure.core.serialization.ToApiJsonSerializer;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.security.data.TenantOidcConfigData;
import org.apache.fineract.infrastructure.security.domain.OidcFederationType;
import org.apache.fineract.infrastructure.security.exception.NoAuthorizationException;
import org.apache.fineract.infrastructure.security.service.PlatformSecurityContext;
import org.apache.fineract.infrastructure.security.service.TenantOidcConfigService;
import org.apache.fineract.useradministration.domain.AppUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TenantOidcConfigApiResourceTest {

    @Mock
    private PlatformSecurityContext context;
    @Mock
    private TenantOidcConfigService tenantOidcConfigService;
    @Mock
    private ToApiJsonSerializer<TenantOidcConfigData> apiJsonSerializer;

    private FineractProperties.FineractSecurityOidcFederationProperties oidcProperties;
    private TenantOidcConfigApiResource resource;

    @BeforeEach
    void setUp() {
        when(context.authenticatedUser()).thenReturn(mock(AppUser.class));

        oidcProperties = new FineractProperties.FineractSecurityOidcFederationProperties();
        FineractProperties.FineractSecurityProperties security = new FineractProperties.FineractSecurityProperties();
        security.setOidcFederation(oidcProperties);
        FineractProperties fineractProperties = new FineractProperties();
        fineractProperties.setSecurity(security);

        TenantOidcConfig config = TenantOidcConfig.builder().id(1L).tenantId("tenant-b").providerType(OidcFederationType.GENERIC)
                .issuerUri("https://idp.example.com").enabled(true).build();
        when(tenantOidcConfigService.findByTenantId(any())).thenReturn(Optional.of(config));
        when(tenantOidcConfigService.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(apiJsonSerializer.serialize(any())).thenReturn("{}");

        resource = new TenantOidcConfigApiResource(context, tenantOidcConfigService, apiJsonSerializer, fineractProperties);
    }

    @AfterEach
    void tearDown() {
        ThreadLocalContextUtil.reset();
    }

    private void authenticatedIn(String tenantId) {
        ThreadLocalContextUtil.setTenant(FineractPlatformTenant.builder().id(1L).tenantIdentifier(tenantId).name(tenantId).build());
    }

    @Test
    void allowsManagingOwnTenant() {
        authenticatedIn("tenant-b");

        resource.retrieve("tenant-b");
        resource.update("tenant-b", "{\"issuerUri\":\"https://idp.example.com\"}");
        resource.delete("tenant-b");

        verify(tenantOidcConfigService).deleteByTenantId("tenant-b");
    }

    @Test
    void rejectsOtherTenantOnEveryEndpoint() {
        authenticatedIn("tenant-a");

        assertThatThrownBy(() -> resource.retrieve("tenant-b")).isInstanceOf(NoAuthorizationException.class);
        assertThatThrownBy(() -> resource.create("tenant-b", "{}")).isInstanceOf(NoAuthorizationException.class);
        assertThatThrownBy(() -> resource.update("tenant-b", "{}")).isInstanceOf(NoAuthorizationException.class);
        assertThatThrownBy(() -> resource.delete("tenant-b")).isInstanceOf(NoAuthorizationException.class);

        verify(tenantOidcConfigService, never()).save(any());
        verify(tenantOidcConfigService, never()).deleteByTenantId(any());
    }

    @Test
    void rejectsWhenNoTenantContext() {
        assertThatThrownBy(() -> resource.retrieve("tenant-b")).isInstanceOf(NoAuthorizationException.class);
    }

    @Test
    void allowsConfiguredPlatformAdminTenantToManageOtherTenants() {
        oidcProperties.setPlatformAdminTenant("default");
        authenticatedIn("default");

        resource.update("tenant-b", "{\"enabled\":false}");

        verify(tenantOidcConfigService).save(any());
    }

    @Test
    void platformAdminSettingDoesNotGrantOtherTenants() {
        oidcProperties.setPlatformAdminTenant("default");
        authenticatedIn("tenant-a");

        assertThatThrownBy(() -> resource.update("tenant-b", "{}")).isInstanceOf(NoAuthorizationException.class);
        verify(tenantOidcConfigService, never()).save(any());
    }
}
