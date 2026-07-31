package io.sessionlayer.controlplane.authz;

/**
 * Serializes DecisionContext to proto and canonical signed bytes (deterministic
 * serialization; stable across Java protobuf and Rust prost).
 */
public final class DecisionContextCodec {

	private DecisionContextCodec() {
	}

	public static io.sessionlayer.controlplane.grpc.v1.DecisionContext toProto(DecisionContext ctx) {
		io.sessionlayer.controlplane.grpc.v1.DecisionContext.Builder builder = io.sessionlayer.controlplane.grpc.v1.DecisionContext
				.newBuilder().setNodeId(str(ctx.nodeId())).setNodeName(nullToEmpty(ctx.nodeName()))
				.addAllAllowedLogins(ctx.allowedLogins())
				.addAllCapabilities(CapabilityCodec.toProto(ctx.capabilities()))
				.setPrincipal(nullToEmpty(ctx.principal()))
				.setGrantExpiryEpochSeconds(ctx.grantExpiry().getEpochSecond()).setPolicyEpoch(ctx.policyEpoch())
				.setDecisionTtlSeconds(ctx.decisionTtl().toSeconds()).setGatewayId(str(ctx.gatewayId()))
				.setSessionId(str(ctx.sessionId())).setSourceAddress(nullToEmpty(ctx.sourceAddress()))
				.setIssuedAtEpochSeconds(ctx.issuedAt().getEpochSecond()).setIdentity(nullToEmpty(ctx.identity()))
				.addAllIdentityGroups(ctx.identityGroups()).addAllNodeLabels(ctx.nodeLabels());
		// Emit NON-standing models only; STANDING stays UNSPECIFIED for N-1
		// byte-identical compat.
		io.sessionlayer.controlplane.grpc.v1.AccessModel model = accessModel(ctx.accessModel());
		if (model != io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_UNSPECIFIED) {
			builder.setAccessModel(model);
		}
		// Emit idle timeout only when resolved for N-1 byte-identical compat.
		if (ctx.idleTimeoutSeconds() != null && ctx.idleTimeoutSeconds() > 0) {
			builder.setIdleTimeoutSeconds(ctx.idleTimeoutSeconds());
		}
		return builder.build();
	}

	private static io.sessionlayer.controlplane.grpc.v1.AccessModel accessModel(String model) {
		if (model == null) {
			return io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_UNSPECIFIED;
		}
		return switch (model) {
			case "jit" -> io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_JIT;
			case "breakglass" -> io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_BREAKGLASS;
			default -> io.sessionlayer.controlplane.grpc.v1.AccessModel.ACCESS_MODEL_UNSPECIFIED;
		};
	}

	public static byte[] canonicalBytes(io.sessionlayer.controlplane.grpc.v1.DecisionContext proto) {
		return proto.toByteArray();
	}

	private static String str(java.util.UUID id) {
		return id == null ? "" : id.toString();
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
