package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * The chain columns are for a reader who sees the whole stream: a sequence
 * number over a filtered view discloses how many events were filtered out, and
 * a linkage walk over one proves nothing about the rows it never saw.
 */
class AuditChainFieldsIT extends AbstractConfigApiIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private AuditEventStore store;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private ServiceAccountRepository serviceAccounts;
	@Autowired
	private MachineIdentityService machineIdentity;
	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private RoleBindingRepository bindings;

	@Test
	void anUnscopedReaderSeesTheChainColumnsAndAScopedOneDoesNot() {
		UUID run = UUID.randomUUID();
		AuditEvent stored = seed("u-" + run.toString().substring(0, 8), run, Map.of("env", "prod"));
		assertThat(stored.recordHash()).isNotBlank();

		String unscoped = tokenWith("svc-chain-all-" + run, PlatformPermissions.AUDIT_READ);
		JsonNode open = search(unscoped, run).body().get("items").get(0);
		assertThat(open.get("seq").asLong()).isEqualTo(stored.seq());
		assertThat(open.get("prevHash").asString()).isEqualTo(stored.prevHash());
		assertThat(open.get("recordHash").asString()).isEqualTo(stored.recordHash());

		String scoped = scopedToken("svc-chain-scoped-" + run, nodeLabelScope("env", "prod"));
		// The event is IN scope for this binding, so the reader gets the row and is
		// denied only the chain - the omission is not an artefact of a filtered row.
		Response response = search(scoped, run);
		JsonNode narrowed = response.body().get("items").get(0);
		assertThat(narrowed.get("id").asString()).isEqualTo(stored.id().toString());
		assertThat(isAbsent(narrowed, "seq")).isTrue();
		assertThat(isAbsent(narrowed, "prevHash")).isTrue();
		assertThat(isAbsent(narrowed, "recordHash")).isTrue();
		assertThat(response.raw()).doesNotContain(stored.recordHash()).doesNotContain(stored.prevHash());
	}

	@Test
	void theSingleEventReadHonoursTheSameSplit() {
		UUID run = UUID.randomUUID();
		AuditEvent stored = seed("u-" + run.toString().substring(0, 8), run, Map.of("env", "prod"));

		String unscoped = tokenWith("svc-chainget-all-" + run, PlatformPermissions.AUDIT_READ);
		JsonNode open = objectMapper.readTree(get(unscoped, stored.id()));
		assertThat(open.get("recordHash").asString()).isEqualTo(stored.recordHash());
		assertThat(open.get("seq").asLong()).isEqualTo(stored.seq());

		String scoped = scopedToken("svc-chainget-scoped-" + run, nodeLabelScope("env", "prod"));
		byte[] raw = get(scoped, stored.id());
		JsonNode narrowed = objectMapper.readTree(raw);
		assertThat(narrowed.get("id").asString()).isEqualTo(stored.id().toString());
		assertThat(isAbsent(narrowed, "seq")).isTrue();
		assertThat(isAbsent(narrowed, "recordHash")).isTrue();
		assertThat(new String(raw, StandardCharsets.UTF_8)).doesNotContain(stored.recordHash());
	}

	/**
	 * Anchored on rows this test appended through the store, deliberately, rather
	 * than on whatever happens to be newest. Sibling suites insert audit rows
	 * straight through the repository without calling {@code withChain}, so the
	 * table legitimately contains rows with no {@code record_hash} - the production
	 * reader allows for that too ({@code findChainOrdered} filters on
	 * {@code record_hash IS NOT NULL}). A walk that assumed every row in the stream
	 * is chained would be asserting something the schema does not promise.
	 */
	@Test
	void anUnscopedReaderCanCaptureTheHeadAndWalkLinkage() {
		String unscoped = tokenWith("svc-chain-walk-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		List<AuditEvent> appended = new ArrayList<>();
		for (int i = 0; i < 4; i++) {
			appended.add(seed("chain-walk", UUID.randomUUID(), Map.of()));
		}
		AuditEvent newest = appended.get(appended.size() - 1);

		JsonNode head = unfiltered(unscoped, 1).get("items").get(0);
		assertThat(head.get("id").asString()).isEqualTo(newest.id().toString());
		assertThat(head.get("seq").asLong()).isEqualTo(newest.seq());
		assertThat(head.get("recordHash").asString()).isEqualTo(newest.recordHash());

		// Linkage across the four we appended: consecutive in the chain because
		// nothing else wrote between them, so prevHash[n+1] must equal recordHash[n].
		Map<UUID, JsonNode> page = new LinkedHashMap<>();
		unfiltered(unscoped, 50).get("items")
				.forEach(item -> page.put(UUID.fromString(item.get("id").asString()), item));
		List<JsonNode> ours = appended.stream().map(event -> page.get(event.id())).toList();
		assertThat(ours).doesNotContainNull().hasSize(4);
		for (int i = 1; i < ours.size(); i++) {
			assertThat(ours.get(i).get("seq").asLong()).isEqualTo(ours.get(i - 1).get("seq").asLong() + 1);
			assertThat(ours.get(i).get("prevHash").asString()).isEqualTo(ours.get(i - 1).get("recordHash").asString());
		}
	}

	private record Response(JsonNode body, String raw) {
	}

	private AuditEvent seed(String actor, UUID correlationId, Map<String, String> nodeLabels) {
		store.record(AuditRecord.builder(actor, null, "chain.probe", "success").correlationId(correlationId)
				.nodeLabels(nodeLabels).build()).block();
		return auditEvents.findAll().filter(event -> correlationId.equals(event.correlationId()))
				.filter(event -> "chain.probe".equals(event.action())).blockFirst();
	}

	private static ObjectNode nodeLabelScope(String key, String value) {
		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode().put(key, value));
		return scope;
	}

	private static boolean isAbsent(JsonNode item, String field) {
		JsonNode value = item.get(field);
		return value == null || value.isNull();
	}

	private Response search(String token, UUID correlationId) {
		byte[] raw = client.get().uri("/v1/audit-events?correlationId=" + correlationId)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().expectBody().returnResult()
				.getResponseBody();
		return new Response(objectMapper.readTree(raw), new String(raw, StandardCharsets.UTF_8));
	}

	private JsonNode unfiltered(String token, int limit) {
		return objectMapper
				.readTree(client.get().uri("/v1/audit-events?limit=" + limit).header("Authorization", "Bearer " + token)
						.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody());
	}

	private byte[] get(String token, UUID auditEventId) {
		return client.get().uri("/v1/audit-events/" + auditEventId).header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().expectBody().returnResult().getResponseBody();
	}

	private String scopedToken(String saName, JsonNode scope) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		PlatformRole role = roles.save(PlatformRole.create("role-" + UUID.randomUUID(),
				List.of(PlatformPermissions.AUDIT_READ), "test", "default")).block();
		bindings.save(RoleBinding.create(role.id(), "user", saName, scope, "default")).block();
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
