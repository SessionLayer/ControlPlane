package io.sessionlayer.controlplane.authz;

import java.util.List;

/**
 * Per-node connectivity + host-identity for authorized target (public material
 * only: host CA keys, enrollment certs, pinned keys; never private/TOFU). Empty
 * verification set = misconfigured (fail-closed). owner* fields carry HA
 * presence/ownership (outbound agents only, fresh owner required).
 */
public record NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
		List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
		List<byte[]> hostCertificates, String owningGatewayId, String owningGatewayAddr, long ownerNonce,
		String ownerNonceId) {

	/** Build with no HA owner. */
	public NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
			List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
			List<byte[]> hostCertificates) {
		this(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals, pinnedHostKeys, hostCertificates, "",
				"", 0L, "");
	}

	/**
	 * A copy carrying the fresh HA presence owner (id, advertise addr, fencing
	 * nonce).
	 */
	public NodeConnectionInfo withOwner(String owningGatewayId, String owningGatewayAddr, long ownerNonce,
			String ownerNonceId) {
		return new NodeConnectionInfo(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals,
				pinnedHostKeys, hostCertificates, owningGatewayId, owningGatewayAddr, ownerNonce, ownerNonceId);
	}

	/**
	 * Whether a fresh HA presence owner is present (routing populates the wire).
	 */
	public boolean hasOwner() {
		return owningGatewayId != null && !owningGatewayId.isEmpty();
	}

	/**
	 * The connectivity model resolved from inventory {@code node.connector_kind}.
	 */
	public enum ConnectorModel {
		AGENTLESS, OUTBOUND_AGENT, UNSPECIFIED;

		public static ConnectorModel fromInventory(String connectorKind) {
			return switch (connectorKind == null ? "" : connectorKind) {
				case "agentless" -> AGENTLESS;
				case "agent" -> OUTBOUND_AGENT;
				default -> UNSPECIFIED;
			};
		}
	}

	/** Whether any enrollment-anchored trust is present (host CA or pinned key). */
	public boolean hasHostVerification() {
		return !hostCaKeys.isEmpty() || !pinnedHostKeys.isEmpty();
	}
}
