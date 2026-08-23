package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditChainVerifier;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.CapturingAuditForwarder;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

class AuditForwarderSeamIT extends AbstractDataIT {

	@TestConfiguration
	static class Doubles {
		@Bean
		@Primary
		CapturingAuditForwarder capturingAuditForwarder() {
			return new CapturingAuditForwarder();
		}
	}

	@Autowired
	private AuditEventStore audit;

	@Autowired
	private AuditEventRepository audits;

	@Autowired
	private CapturingAuditForwarder forwarder;

	@Test
	void everyCommittedEventIsShippedOffBoxThroughTheSwappedForwarder() {
		UUID session = UUID.randomUUID();
		audit.record("alice@corp", "node-1", "seam.forward", "success", session, null, Map.of("k", "v")).block();

		List<AuditEvent> forwarded = forwarder.captured().stream().filter(e -> "seam.forward".equals(e.action()))
				.toList();
		assertThat(forwarded).hasSize(1);
		assertThat(forwarded.getFirst().recordHash()).isNotNull();
		assertThat(forwarded.getFirst().actor()).isEqualTo("alice@corp");

		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain).anyMatch(e -> "seam.forward".equals(e.action()));
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();
	}
}
