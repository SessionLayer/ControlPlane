package io.sessionlayer.controlplane.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformAuthorization.ScopeGrant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

class AuditEventSearchServiceTest {

	private AuditQuery query(String action) {
		return new AuditQuery(null, null, action, null, null, null, null, null, null, null, null, Map.of(), null,
				List.of(), null, 50);
	}

	@Test
	void searchReturnsWhatWasRecordedThroughTheInterface() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		for (int i = 0; i < 3; i++) {
			store.record("alice", "node-" + i, "probe.run", "success", UUID.randomUUID(), UUID.randomUUID(),
					Map.of("i", Integer.toString(i))).block();
		}

		AuditPage page = service.search(query("probe.run"), "admin").block();
		assertThat(page.items()).hasSize(3).allSatisfy(e -> assertThat(e.action()).isEqualTo("probe.run"));

		assertThat(service.search(query("audit.search"), "admin").block().items()).isNotEmpty();
	}

	@Test
	void getReturnsTheEventAndAuditsTheAccess() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		store.record("bob", "node", "probe.get", "success", null, null, Map.of()).block();
		AuditEvent seeded = store.search(query("probe.get")).block().items().get(0);

		AuditEvent got = service.get(seeded.id(), "admin", ScopeGrant.all()).block();
		assertThat(got.id()).isEqualTo(seeded.id());
		assertThat(service.search(query("audit.get"), "admin").block().items()).isNotEmpty();
	}

	/**
	 * The chain columns are stripped inside the service, so a controller cannot
	 * assemble a response carrying them from a scope-filtered read even if it
	 * copies every field unconditionally - which is what it does.
	 */
	@Test
	void aScopedReadNeverCarriesTheChainColumns() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		store.record("carol", "node", "probe.scope", "success", null, null, Map.of()).block();
		AuditEvent seeded = store.search(query("probe.scope")).block().items().get(0);
		assertThat(seeded.recordHash()).isNotBlank();

		// A scope the event IS inside, so the row comes back and only the chain is
		// withheld - not a row that was filtered out anyway.
		ObjectNode scope = JsonNodeFactory.instance.objectNode();
		scope.set("users", JsonNodeFactory.instance.arrayNode().add("carol"));
		AuditEvent scoped = service.get(seeded.id(), "admin", ScopeGrant.scoped(List.of(scope))).block();
		assertThat(scoped.id()).isEqualTo(seeded.id());
		assertThat(scoped.recordHash()).isNull();
		assertThat(scoped.prevHash()).isNull();
		assertThat(scoped.seq()).isNull();

		AuditQuery scopedQuery = new AuditQuery(null, null, "probe.scope", null, null, null, null, null, null, null,
				null, Map.of(), null, List.of(scope), null, 50);
		assertThat(service.search(scopedQuery, "admin").block().items()).isNotEmpty()
				.allSatisfy(event -> assertThat(event.recordHash()).isNull());

		assertThat(service.search(query("probe.scope"), "admin").block().items()).isNotEmpty()
				.allSatisfy(event -> assertThat(event.recordHash()).isNotBlank());
	}

	@Test
	void readsLeaveTheChainVerifiable() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		store.record("carol", null, "probe.chain", "success", null, null, Map.of()).block();
		assertThat(store.verifyChain().block().valid()).isTrue();

		service.search(query("probe.chain"), "admin").block();
		assertThat(store.verifyChain().block().valid()).isTrue();
	}
}
