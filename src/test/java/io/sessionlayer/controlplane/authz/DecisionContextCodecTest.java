package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DecisionContextCodecTest {

	@Test
	void serialisesIdentityGroupsAndNodeLabels() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-a", List.of("deploy"), List.of("shell"),
				"deploy", Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(),
				UUID.randomUUID(), "10.0.0.5", Instant.now(), "alice", List.of("admins", "oncall"),
				List.of("env=prod", "tier=db"), "standing", null);

		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(ctx);

		assertThat(proto.getIdentity()).isEqualTo("alice");
		assertThat(proto.getIdentityGroupsList()).containsExactly("admins", "oncall");
		assertThat(proto.getNodeLabelsList()).containsExactly("env=prod", "tier=db");
		assertThat(proto.getNodeName()).isEqualTo("node-a");
		assertThat(proto.getPrincipal()).isEqualTo("deploy");
		assertThat(proto.getPolicyEpoch()).isEqualTo(7L);
		assertThat(proto.getAccessModel())
				.isEqualTo(io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_UNSPECIFIED);
	}

	@Test
	void emitsNonStandingAccessModel() {
		DecisionContext jit = new DecisionContext(UUID.randomUUID(), "node-a", List.of("deploy"), List.of("shell"),
				"deploy", Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(),
				UUID.randomUUID(), "10.0.0.5", Instant.now(), "alice", List.of(), List.of(), "jit", null);
		assertThat(DecisionContextCodec.toProto(jit).getAccessModel())
				.isEqualTo(io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_JIT);

		DecisionContext bg = new DecisionContext(UUID.randomUUID(), "node-a", List.of("root"), List.of("shell"), "root",
				Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(), UUID.randomUUID(),
				"10.0.0.5", Instant.now(), "root", List.of(), List.of(), "breakglass", null);
		assertThat(DecisionContextCodec.toProto(bg).getAccessModel())
				.isEqualTo(io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_BREAKGLASS);
	}

	@Test
	void toleratesEmptyIdentityAndCollections() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-b", List.of(), List.of(), "", Instant.now(),
				0L, Duration.ZERO, UUID.randomUUID(), UUID.randomUUID(), "", Instant.now(), null, List.of(), List.of(),
				null, null);

		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(ctx);

		assertThat(proto.getIdentity()).isEmpty();
		assertThat(proto.getIdentityGroupsList()).isEmpty();
		assertThat(proto.getNodeLabelsList()).isEmpty();
	}

	@Test
	void emitsAResolvedIdleTimeout() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-a", List.of("deploy"), List.of("shell"),
				"deploy", Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(),
				UUID.randomUUID(), "10.0.0.5", Instant.now(), "alice", List.of(), List.of(), "standing", 300);

		assertThat(DecisionContextCodec.toProto(ctx).getIdleTimeoutSeconds()).isEqualTo(300L);
	}

	@Test
	void noResolvedIdleTimeoutKeepsThePreS25BytesIdentical() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-a", List.of("deploy"), List.of("shell"),
				"deploy", Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(),
				UUID.randomUUID(), "10.0.0.5", Instant.now(), "alice", List.of("admins"), List.of("env=prod"),
				"standing", null);

		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(ctx);
		byte[] bytes = DecisionContextCodec.canonicalBytes(proto);

		assertThat(proto.getIdleTimeoutSeconds()).isZero();
		// Field 17 is truly ABSENT, not encoded-as-zero: clearing it changes nothing,
		// so a no-idle-policy decision maintains byte-identity across versions.
		assertThat(proto.toBuilder().clearIdleTimeoutSeconds().build().toByteArray()).isEqualTo(bytes);
	}
}
