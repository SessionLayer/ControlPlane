package io.sessionlayer.controlplane.gateway;

public class GatewayRequestException extends RuntimeException {

	public enum Reason {
		UNAUTHENTICATED, PERMISSION_DENIED, FAILED_PRECONDITION, INVALID_ARGUMENT
	}

	private final Reason reason;

	public GatewayRequestException(Reason reason, String publicMessage) {
		super(publicMessage);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
