package io.sessionlayer.controlplane.authz;

import java.util.List;

public record NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
		List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
		List<byte[]> hostCertificates, String owningGatewayId, String owningGatewayAddr, long ownerNonce,
		String ownerNonceId) {

	public NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
			List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
			List<byte[]> hostCertificates) {
		this(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals, pinnedHostKeys, hostCertificates, "",
				"", 0L, "");
	}

	public NodeConnectionInfo withOwner(String owningGatewayId, String owningGatewayAddr, long ownerNonce,
			String ownerNonceId) {
		return new NodeConnectionInfo(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals,
				pinnedHostKeys, hostCertificates, owningGatewayId, owningGatewayAddr, ownerNonce, ownerNonceId);
	}

	public boolean hasOwner() {
		return owningGatewayId != null && !owningGatewayId.isEmpty();
	}

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

	public boolean hasHostVerification() {
		return !hostCaKeys.isEmpty() || !pinnedHostKeys.isEmpty();
	}
}
