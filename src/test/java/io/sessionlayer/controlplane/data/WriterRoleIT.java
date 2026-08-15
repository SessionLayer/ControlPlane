package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

class WriterRoleIT extends AbstractDataIT {

	@Autowired
	private DatabaseClient db;

	@Autowired
	private AuditEventRepository audits;

	@Autowired
	private NodeRepository nodes;

	@Autowired
	private tools.jackson.databind.ObjectMapper objectMapper;

	private String currentUser() {
		return db.sql("SELECT current_user").map(row -> row.get(0, String.class)).one().block();
	}

	@Test
	void runtimeConnectsAsTheRestrictedNonSuperuserRole() {
		assertThat(currentUser()).isEqualTo("cp_runtime");
		Boolean isSuper = db.sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
				.map(row -> row.get(0, Boolean.class)).one().block();
		assertThat(isSuper).isFalse();
	}

	@Test
	void cannotDropOrAlterTables() {
		StepVerifier.create(db.sql("DROP TABLE runtime.node").then()).verifyError();
		StepVerifier.create(db.sql("ALTER TABLE runtime.node ADD COLUMN hacked text").then()).verifyError();
		assertThat(nodes.count().block()).isNotNull();
	}

	@Test
	void cannotDisableTheAppendOnlyTrigger() {
		StepVerifier
				.create(db.sql("ALTER TABLE runtime.audit_event DISABLE TRIGGER audit_event_no_update_delete").then())
				.verifyError();
	}

	@Test
	void cannotUpdateOrDeleteAuditEvent() {
		audits.save(AuditEvent.create(Instant.now(), "writer-role", null, "probe", "success", null, null, null, null,
				null, null, null, null)).block();
		StepVerifier.create(db.sql("UPDATE runtime.audit_event SET actor = 'x'").then()).verifyError();
		StepVerifier.create(db.sql("DELETE FROM runtime.audit_event").then()).verifyError();
		String part = "runtime.audit_event_" + java.time.YearMonth.now(java.time.ZoneOffset.UTC)
				.format(java.time.format.DateTimeFormatter.ofPattern("yyyyMM"));
		StepVerifier.create(db.sql("UPDATE " + part + " SET actor = 'x'").then()).verifyError();
	}

	@Test
	void cannotDropAuditPartitionsViaThePruneFunction() {
		StepVerifier.create(db.sql("SELECT runtime.audit_prune_before(now())").then()).verifyError();
		Long ok = db.sql("SELECT 1 WHERE runtime.audit_ensure_partition(date_trunc('month', now())::date) IS NOT NULL")
				.map(row -> row.get(0, Long.class)).one().block();
		assertThat(ok).isEqualTo(1L);
	}

	@Test
	void cannotDeleteOrUpdateCaKeyMaterial() {
		StepVerifier.create(db.sql("DELETE FROM runtime.ca_key_material").then()).verifyError();
		StepVerifier.create(db.sql("UPDATE runtime.ca_key_material SET updated_at = now()").then()).verifyError();
	}

	@Test
	void recordingTokenIsInsertUpdateSelectButNeverDeletable() {
		java.util.UUID id = Uuids.v7();
		db.sql("INSERT INTO runtime.recording_token (id, token_hash, gateway_id, session_id, principal, expires_at) "
				+ "VALUES (:id, :h, :g, :s, 'deploy', now() + interval '2 minutes')").bind("id", id)
				.bind("h", "hash-" + id).bind("g", Uuids.v7()).bind("s", Uuids.v7()).then().block();
		db.sql("UPDATE runtime.recording_token SET used = true WHERE id = :id").bind("id", id).then().block();
		StepVerifier.create(db.sql("DELETE FROM runtime.recording_token WHERE id = :id").bind("id", id).then())
				.verifyError();
	}

	@Test
	void canInsertAuditAndDoNormalCrud() {
		var e = audits.save(AuditEvent.create(Instant.now(), "writer-role-ok", null, "login", "success", null, null,
				null, null, null, null, null, null)).block();
		assertThat(audits.findById(e.id()).block()).isNotNull();

		var n = nodes.save(
				Node.create("writer-role-node", null, objectMapper.readTree("{}"), "agentless", "active", "10.9.9.9"))
				.block();
		var updated = nodes.save(
				new Node(n.id(), n.name(), n.nodePolicyName(), n.resolvedLabels(), n.connectorKind(), "quarantined",
						n.address(), "manual", "admin@x", Instant.now(), n.version(), n.createdAt(), n.updatedAt()))
				.block();
		assertThat(updated.status()).isEqualTo("quarantined");
	}
}
