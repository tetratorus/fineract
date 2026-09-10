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
package org.apache.fineract.infrastructure.dataqueries.service;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.apache.fineract.commands.domain.CommandSource;
import org.apache.fineract.infrastructure.core.exception.PlatformDataIntegrityException;
import org.apache.fineract.infrastructure.core.serialization.FromJsonHelper;
import org.apache.fineract.infrastructure.core.service.database.DatabaseSpecificSQLGenerator;
import org.apache.fineract.infrastructure.core.service.database.DatabaseTypeResolver;
import org.apache.fineract.infrastructure.dataqueries.data.EntityTables;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DatatableRejectionCleanupServiceTest {

    private static final String DATATABLE_NAME = "dt_test_loan";
    private static final String CORE_TABLE_NAME = "m_loan";

    @Mock
    private JdbcTemplate jdbcTemplate;
    @Mock
    private DatabaseSpecificSQLGenerator sqlGenerator;
    @Mock
    private DatabaseTypeResolver databaseTypeResolver;
    @Mock
    private DatatableUtil datatableUtil;
    @Spy
    private FromJsonHelper fromJsonHelper = new FromJsonHelper();

    @InjectMocks
    private DatatableRejectionCleanupService underTest;

    @BeforeEach
    void setUp() {
        when(databaseTypeResolver.isMySQL()).thenReturn(true);
        when(sqlGenerator.escape(anyString())).thenAnswer(invocation -> "`" + invocation.getArgument(0) + "`");
        when(datatableUtil.getFKField(EntityTables.LOAN)).thenReturn("loan_id");
    }

    @Test
    void dropsTableCreatedByTheRejectedCommand() {
        registeredDatatableCount(DATATABLE_NAME, 0);
        datatableForeignKeyCount(DATATABLE_NAME, 1);
        datatableColumnCount(DATATABLE_NAME, 3);

        underTest.cleanup(rejectedCreateDatatable(DATATABLE_NAME));

        verify(jdbcTemplate).execute("DROP TABLE IF EXISTS `" + DATATABLE_NAME + "`");
    }

    @Test
    void keepsTableThatWasNotCreatedByTheRejectedCommand() {
        registeredDatatableCount(CORE_TABLE_NAME, 0);
        datatableForeignKeyCount(CORE_TABLE_NAME, 0);
        datatableColumnCount(CORE_TABLE_NAME, 3);

        underTest.cleanup(rejectedCreateDatatable(CORE_TABLE_NAME));

        verify(jdbcTemplate, never()).execute(anyString());
    }

    @Test
    void keepsRegisteredDatatable() {
        registeredDatatableCount(DATATABLE_NAME, 1);
        datatableForeignKeyCount(DATATABLE_NAME, 1);
        datatableColumnCount(DATATABLE_NAME, 3);

        underTest.cleanup(rejectedCreateDatatable(DATATABLE_NAME));

        verify(jdbcTemplate, never()).execute(anyString());
    }

    @Test
    void keepsTableWithNameFailingDatatableNameValidation() {
        String injectedName = "dt_test`; DROP TABLE m_loan; --";
        doThrow(new PlatformDataIntegrityException("error.msg.datatables.datatable.invalid.name.regex", "Invalid data table name."))
                .when(datatableUtil).validateDatatableName(injectedName);

        underTest.cleanup(rejectedCreateDatatable(injectedName));

        verify(jdbcTemplate, never()).execute(anyString());
    }

    @Test
    void keepsTableWithoutTheDatatableAuditColumns() {
        registeredDatatableCount(CORE_TABLE_NAME, 0);
        datatableForeignKeyCount(CORE_TABLE_NAME, 1);
        datatableColumnCount(CORE_TABLE_NAME, 1);

        underTest.cleanup(rejectedCreateDatatable(CORE_TABLE_NAME));

        verify(jdbcTemplate, never()).execute(anyString());
    }

    @Test
    void keepsTableWhenCommandJsonCannotBeRead() {
        CommandSource commandSource = new CommandSource();
        commandSource.setActionName("CREATE");
        commandSource.setEntityName("DATATABLE");
        commandSource.setCommandAsJson("{\"datatableName\":");

        underTest.cleanup(commandSource);

        verify(jdbcTemplate, never()).execute(anyString());
    }

    private void registeredDatatableCount(String datatableName, Integer count) {
        when(jdbcTemplate.queryForObject(contains("x_registered_table"), eq(Integer.class), eq(datatableName))).thenReturn(count);
    }

    private void datatableForeignKeyCount(String datatableName, Integer count) {
        when(jdbcTemplate.queryForObject(contains("TABLE_CONSTRAINTS"), eq(Integer.class), eq(datatableName),
                eq("fk_" + datatableName + "_loan_id"))).thenReturn(count);
    }

    private void datatableColumnCount(String datatableName, Integer count) {
        when(jdbcTemplate.queryForObject(contains("information_schema.COLUMNS"), eq(Integer.class), eq(datatableName), eq("loan_id"),
                eq("created_at"), eq("updated_at"))).thenReturn(count);
    }

    private CommandSource rejectedCreateDatatable(String datatableName) {
        CommandSource commandSource = new CommandSource();
        commandSource.setActionName("CREATE");
        commandSource.setEntityName("DATATABLE");
        commandSource.setCommandAsJson(
                "{\"datatableName\":\"" + datatableName.replace("\"", "\\\"") + "\",\"apptableName\":\"m_loan\",\"columns\":[]}");
        return commandSource;
    }
}
