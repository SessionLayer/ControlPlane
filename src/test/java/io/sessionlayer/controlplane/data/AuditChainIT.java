package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditChainVerifier;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

class AuditChainIT extends AbstractDataIT {

	@Autowired
	private AuditEventStore audit;

	@Autowired
	private AuditEventRepository audits;

	@Test
	void writesLinkIntoAVerifiableChain() {
		UUID session = UUID.randomUUID();
		for (int i = 0; i < 5; i++) {
			audit.record("alice@corp", "node-" + i, "chain.probe", "success", session, UUID.randomUUID(),
					Map.of("i", Integer.toString(i))).block();
		}
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain).isNotEmpty();
		assertThat(chain).allSatisfy(e -> {
			assertThat(e.recordHash()).isNotNull();
			assertThat(e.prevHash()).isNotNull();
		});
		AuditChainVerifier.Result result = AuditChainVerifier.verify(chain);
		assertThat(result.valid()).as("recomputed chain: %s", result.failure()).isTrue();
	}

	@Test
	void aMutatedRowBreaksTheChain() {
		audit.record("mallory@corp", "node-x", "chain.mutate", "success", UUID.randomUUID(), null, Map.of("k", "v"))
				.block();
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();

		List<AuditEvent> tampered = new ArrayList<>(chain);
		AuditEvent v = tampered.get(tampered.size() - 1);
		AuditEvent mutated = new AuditEvent(v.id(), v.occurredAt(), "TAMPERED", v.subject(), v.action(), v.outcome(),
				v.correlationId(), v.sessionId(), v.nodeId(), v.nodeLabels(), v.sourceIp(), v.accessModel(),
				v.capabilities(), v.detail(), v.prevHash(), v.recordHash(), v.version(), v.createdAt(), v.seq());
		tampered.set(tampered.size() - 1, mutated);
		AuditChainVerifier.Result result = AuditChainVerifier.verify(tampered);
		assertThat(result.valid()).isFalse();
		assertThat(result.failure()).contains("record_hash mismatch");
	}

	@Test
	void concurrentWritesSerializeWithoutForkingTheChain() {
		int concurrency = 32;
		UUID session = UUID.randomUUID();
		Flux.range(0, concurrency)
				.flatMap(i -> audit.record("racer@corp", "node", "chain.concurrent", "success", session, null,
						Map.of("i", Integer.toString(i))).subscribeOn(Schedulers.parallel()), concurrency)
				.then().block();

		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain.size()).isGreaterThanOrEqualTo(concurrency);
		AuditChainVerifier.Result result = AuditChainVerifier.verify(chain);
		assertThat(result.valid()).as("recomputed chain: %s", result.failure()).isTrue();
		assertThat(chain.stream().map(AuditEvent::prevHash).toList()).doesNotHaveDuplicates();
	}

	@Test
	void aRemovedRowBreaksTheChain() {
		for (int i = 0; i < 3; i++) {
			audit.record("carol@corp", null, "chain.remove", "success", UUID.randomUUID(), null, Map.of()).block();
		}
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain.size()).isGreaterThanOrEqualTo(3);
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();

		List<AuditEvent> excised = new ArrayList<>(chain);
		excised.remove(excised.size() - 2);
		AuditChainVerifier.Result result = AuditChainVerifier.verify(excised);
		assertThat(result.valid()).isFalse();
		assertThat(result.failure()).contains("prev_hash link broken");
	}
}
