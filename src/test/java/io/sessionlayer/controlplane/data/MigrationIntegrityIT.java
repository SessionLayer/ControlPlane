package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

class MigrationIntegrityIT extends AbstractDataIT {

	@Autowired
	private DatabaseClient db;

	@Autowired
	private Flyway flyway;

	@Test
	void allMigrationsAppliedThroughLatest() {
		Integer maxVersion = db.sql("SELECT max(version::int) AS v FROM flyway_schema_history WHERE success = true")
				.map(row -> row.get("v", Integer.class)).one().block();
		assertThat(maxVersion).isEqualTo(36);

		Long failed = db.sql("SELECT count(*) AS c FROM flyway_schema_history WHERE success = false")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(failed).isZero();
	}

	@Test
	void bothSchemasExist() {
		Long schemas = db
				.sql("SELECT count(*) AS c FROM information_schema.schemata "
						+ "WHERE schema_name IN ('config','runtime')")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(schemas).isEqualTo(2);
	}

	@Test
	void allBaseEntityTablesExist() {
		Long tables = db
				.sql("SELECT count(*) AS c FROM information_schema.tables "
						+ "WHERE table_schema IN ('config','runtime') AND table_type = 'BASE TABLE' "
						+ "AND NOT (table_schema = 'runtime' AND table_name LIKE 'audit\\_event\\_%')")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(tables).isEqualTo(41L); // 12 config + 29 runtime

		for (String qualified : new String[]{"runtime.ssh_session", "runtime.access_lock", "runtime.audit_event",
				"runtime.recording_ref", "runtime.recording_token", "runtime.presence", "config.dp_rule",
				"config.ca_config", "runtime.breakglass_credential", "runtime.breakglass_offline_code",
				"runtime.breakglass_token", "runtime.jit_request", "runtime.breakglass_activation"}) {
			String[] parts = qualified.split("\\.");
			Long found = db
					.sql("SELECT count(*) AS c FROM information_schema.tables "
							+ "WHERE table_schema = :s AND table_name = :t")
					.bind("s", parts[0]).bind("t", parts[1]).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("table %s exists", qualified).isEqualTo(1L);
		}
	}

	@Test
	void configOriginDefaultsToDefault() {
		UUID id = Uuids.v7();
		db.sql("INSERT INTO config.capability_def (id, name) VALUES (:id, 'exec')").bind("id", id).fetch().rowsUpdated()
				.block();
		String origin = db.sql("SELECT origin FROM config.capability_def WHERE id = :id").bind("id", id)
				.map(row -> row.get("origin", String.class)).one().block();
		assertThat(origin).isEqualTo("default");
	}

	@Test
	void runtimeTablesHaveNoOriginColumn() {
		Long withOrigin = db
				.sql("SELECT count(*) AS c FROM information_schema.columns "
						+ "WHERE table_schema = 'runtime' AND column_name = 'origin'")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(withOrigin).isZero();
	}

	@Test
	void recordingCustomerKeyAndTokenSchemaLanded() {
		for (String column : new String[]{"recording_customer_public_key", "recording_key_seal_algorithm",
				"recording_key_ref", "recording_retention_days", "recording_strict_default"}) {
			Long found = db.sql("SELECT count(*) AS c FROM information_schema.columns "
					+ "WHERE table_schema = 'config' AND table_name = 'operator_settings' AND column_name = :col")
					.bind("col", column).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("operator_settings.%s exists", column).isEqualTo(1L);
		}
		for (String column : new String[]{"token_hash", "gateway_id", "session_id", "node_id", "principal", "used"}) {
			Long found = db.sql("SELECT count(*) AS c FROM information_schema.columns "
					+ "WHERE table_schema = 'runtime' AND table_name = 'recording_token' AND column_name = :col")
					.bind("col", column).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("recording_token.%s exists", column).isEqualTo(1L);
		}
	}

	@Test
	void thePermissionCheckAdmitsEveryPlatformPermission() {
		// The first-admin bootstrap role carries PlatformPermissions.ALL, so a missed
		// CHECK widening breaks bootstrap rather than failing here.
		String constraint = db
				.sql("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint "
						+ "WHERE conname = 'platform_role_permissions_check'")
				.map(row -> row.get("d", String.class)).one().block();
		assertThat(constraint).isNotNull();
		for (String permission : PlatformPermissions.ALL) {
			assertThat(constraint).as("CHECK admits %s", permission).contains("'" + permission + "'");
		}
	}

	@Test
	void secondMigrateIsANoOp() {
		var result = flyway.migrate();
		assertThat(result.migrationsExecuted).isZero();
	}
}
