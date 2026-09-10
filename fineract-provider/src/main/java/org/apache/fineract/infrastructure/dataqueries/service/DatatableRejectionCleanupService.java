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

import static org.apache.fineract.infrastructure.dataqueries.api.DataTableApiConstant.API_PARAM_APPTABLE_NAME;
import static org.apache.fineract.infrastructure.dataqueries.api.DataTableApiConstant.API_PARAM_DATATABLE_NAME;
import static org.apache.fineract.infrastructure.dataqueries.api.DataTableApiConstant.TABLE_REGISTERED_TABLE;

import com.google.gson.JsonElement;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.fineract.commands.domain.CommandSource;
import org.apache.fineract.infrastructure.core.exception.AbstractPlatformDomainRuleException;
import org.apache.fineract.infrastructure.core.exception.PlatformDataIntegrityException;
import org.apache.fineract.infrastructure.core.serialization.FromJsonHelper;
import org.apache.fineract.infrastructure.core.service.database.DatabaseSpecificSQLGenerator;
import org.apache.fineract.infrastructure.core.service.database.DatabaseTypeResolver;
import org.apache.fineract.infrastructure.dataqueries.data.EntityTables;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DatatableRejectionCleanupService implements CleanupService {

    private final JdbcTemplate jdbcTemplate;
    private final DatabaseSpecificSQLGenerator sqlGenerator;
    private final DatabaseTypeResolver databaseTypeResolver;
    private final FromJsonHelper fromJsonHelper;
    private final DatatableUtil datatableUtil;

    @Override
    public void cleanup(CommandSource commandSource) {

        boolean isCreateAction = "CREATE".equals(commandSource.getActionName());
        boolean isDatatableEntity = "DATATABLE".equals(commandSource.getEntityName());
        if (!isCreateAction || !isDatatableEntity) {
            return;
        }

        final JsonElement element = fromJsonHelper.parse(commandSource.getCommandAsJson());
        final String datatableName = fromJsonHelper.extractStringNamed(API_PARAM_DATATABLE_NAME, element);
        final String entityName = fromJsonHelper.extractStringNamed(API_PARAM_APPTABLE_NAME, element);

        if (!isOrphanOfRejectedCommand(commandSource, datatableName, entityName)) {
            return;
        }

        final String sql = "DROP TABLE IF EXISTS " + sqlGenerator.escape(datatableName);
        log.info("Cleaning up orphaned datatable after rejection: {}", datatableName);
        jdbcTemplate.execute(sql);

    }

    /**
     * The command JSON of a rejected command is attacker controlled: it is stored as submitted and the domain
     * validation only runs while the command is being processed. Only a table that this command left behind may be
     * dropped, so the name is re-validated and the table must carry the foreign key constraint that
     * {@link DatatableWriteServiceImpl#createDatatable} generates from this very datatable name, while not being a
     * datatable registered by another (approved) command.
     */
    private boolean isOrphanOfRejectedCommand(final CommandSource commandSource, final String datatableName, final String entityName) {
        if (datatableName == null || entityName == null) {
            log.warn("Skipping cleanup of rejected command {}: datatable or application table name is missing", commandSource.getId());
            return false;
        }
        try {
            datatableUtil.validateDatatableName(datatableName);
        } catch (PlatformDataIntegrityException | AbstractPlatformDomainRuleException e) {
            log.warn("Skipping cleanup of rejected command {}: invalid datatable name", commandSource.getId(), e);
            return false;
        }
        final EntityTables entityTable = EntityTables.fromEntityName(entityName);
        if (entityTable == null) {
            log.warn("Skipping cleanup of rejected command {}: invalid application table name", commandSource.getId());
            return false;
        }
        if (isRegisteredDatatable(datatableName)) {
            log.warn("Skipping cleanup of rejected command {}: datatable is registered", commandSource.getId());
            return false;
        }
        if (!hasDatatableForeignKey(datatableName, datatableUtil.getFKField(entityTable))) {
            log.warn("Skipping cleanup of rejected command {}: table was not created by this command", commandSource.getId());
            return false;
        }
        return true;
    }

    private boolean isRegisteredDatatable(final String datatableName) {
        final String sql = "SELECT count(*) FROM " + TABLE_REGISTERED_TABLE + " WHERE registered_table_name = ?";
        final Integer count = jdbcTemplate.queryForObject(sql, Integer.class, datatableName); // NOSONAR
        return count != null && count > 0;
    }

    private boolean hasDatatableForeignKey(final String datatableName, final String fkColumnName) {
        final String fkName = "fk_" + datatableName.toLowerCase(Locale.ROOT).replaceAll("\\s", "_") + "_" + fkColumnName;
        final String schemaSql = databaseTypeResolver.isMySQL() ? "i.TABLE_SCHEMA = SCHEMA()"
                : "i.table_catalog = current_catalog AND i.table_schema = current_schema";
        final String sql = "SELECT count(*) FROM information_schema.TABLE_CONSTRAINTS i WHERE i.CONSTRAINT_TYPE = 'FOREIGN KEY' AND "
                + schemaSql + " AND i.TABLE_NAME = ? AND i.CONSTRAINT_NAME = ?";
        final Integer count = jdbcTemplate.queryForObject(sql, Integer.class, datatableName, fkName); // NOSONAR
        return count != null && count > 0;
    }
}
