package io.sessionlayer.controlplane.mtls;

import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * Authenticated peer for one RPC (leaf cert + principal ID from SAN URI).
 * Gateways and Agents never overlap; {@link #NONE} is bootstrap-tier.
 */
public record MtlsPeer(UUID gatewayId, UUID agentId, X509Certificate certificate) {

	public static final MtlsPeer NONE = new MtlsPeer(null, null, null);

	public static MtlsPeer gateway(UUID gatewayId, X509Certificate certificate) {
		return new MtlsPeer(gatewayId, null, certificate);
	}

	public static MtlsPeer agent(UUID agentId, X509Certificate certificate) {
		return new MtlsPeer(null, agentId, certificate);
	}

	public boolean authenticated() {
		return gatewayId != null || agentId != null;
	}
}
