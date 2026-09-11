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
package org.apache.fineract.portfolio.group.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.apache.fineract.infrastructure.codes.service.CodeValueReadPlatformService;
import org.apache.fineract.infrastructure.core.data.PaginationParameters;
import org.apache.fineract.infrastructure.core.data.PaginationParametersDataValidator;
import org.apache.fineract.infrastructure.core.exception.PlatformApiDataValidationException;
import org.apache.fineract.infrastructure.core.service.PaginationHelper;
import org.apache.fineract.infrastructure.core.service.SearchParameters;
import org.apache.fineract.infrastructure.core.service.database.DatabaseSpecificSQLGenerator;
import org.apache.fineract.infrastructure.security.service.PlatformSecurityContext;
import org.apache.fineract.infrastructure.security.utils.ColumnValidator;
import org.apache.fineract.organisation.office.service.OfficeReadPlatformService;
import org.apache.fineract.organisation.staff.service.StaffReadService;
import org.apache.fineract.portfolio.client.service.ClientReadPlatformService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@ExtendWith(MockitoExtension.class)
class GroupReadPlatformServiceImplTest {

    @Mock
    private JdbcTemplate jdbcTemplate;
    @Mock
    private PlatformSecurityContext context;
    @Mock
    private OfficeReadPlatformService officeReadPlatformService;
    @Mock
    private StaffReadService staffReadPlatformService;
    @Mock
    private CenterReadPlatformService centerReadPlatformService;
    @Mock
    private CodeValueReadPlatformService codeValueReadPlatformService;
    @Mock
    private PaginationHelper paginationHelper;
    @Mock
    private DatabaseSpecificSQLGenerator sqlGenerator;
    @Mock
    private ColumnValidator columnValidator;
    @Mock
    private ClientReadPlatformService clientReadPlatformService;

    private GroupReadPlatformServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new GroupReadPlatformServiceImpl(jdbcTemplate, context, officeReadPlatformService, staffReadPlatformService,
                centerReadPlatformService, codeValueReadPlatformService, paginationHelper, sqlGenerator,
                new PaginationParametersDataValidator(), columnValidator, clientReadPlatformService);
    }

    @Test
    void retrieveAllRejectsUnsupportedOrderBy() {
        final PaginationParameters parameters = PaginationParameters.builder()
                .orderBy("(select count(*) from m_loan a, m_loan b, m_loan c)").build();

        assertThrows(PlatformApiDataValidationException.class,
                () -> service.retrieveAll(SearchParameters.builder().build(), parameters));

        verify(jdbcTemplate, never()).query(anyString(), any(RowMapper.class), any(Object[].class));
    }

    @Test
    void retrieveAllRejectsUnsupportedSortOrder() {
        final PaginationParameters parameters = PaginationParameters.builder().orderBy("name").sortOrder("asc, (select 1)").build();

        assertThrows(PlatformApiDataValidationException.class,
                () -> service.retrieveAll(SearchParameters.builder().build(), parameters));

        verify(jdbcTemplate, never()).query(anyString(), any(RowMapper.class), any(Object[].class));
    }
}
