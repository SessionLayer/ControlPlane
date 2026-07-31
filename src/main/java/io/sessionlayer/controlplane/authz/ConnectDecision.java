package io.sessionlayer.controlplane.authz;

import java.util.UUID;

/**
 * Orchestrated connect-time outcome. On allow,
 * signedContext/tokens/nodeConnection are present; on deny they are null
 * (fail-closed). trace carries non-content correlation for allow; null on deny.
 */
public record ConnectDecision(boolean allowed, SignedDecisionContext signedContext, String sessionToken,
		String recordingToken, NodeConnectionInfo nodeConnection, TraceInfo trace) {

	public record TraceInfo(String accessModel, UUID nodeId, UUID correlationId) {
	}

	public static ConnectDecision allow(SignedDecisionContext signedContext, String sessionToken, String recordingToken,
			NodeConnectionInfo nodeConnection, TraceInfo trace) {
		return new ConnectDecision(true, signedContext, sessionToken, recordingToken, nodeConnection, trace);
	}

	public static ConnectDecision denied() {
		return new ConnectDecision(false, null, null, null, null, null);
	}
}
