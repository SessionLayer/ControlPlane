package io.sessionlayer.controlplane.agent;

public class AgentJoinException extends RuntimeException {

	public enum Reason {
		UNAUTHENTICATED, PERMISSION_DENIED, FAILED_PRECONDITION, INVALID_ARGUMENT
	}

	private final Reason reason;

	public AgentJoinException(Reason reason, String publicMessage) {
		super(publicMessage);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
