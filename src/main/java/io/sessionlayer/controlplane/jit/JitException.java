package io.sessionlayer.controlplane.jit;

public class JitException extends RuntimeException {

	public enum Reason {
		NOT_FOUND, INVALID, NOT_REQUESTABLE, NOT_PENDING, SELF_APPROVAL, NOT_AN_APPROVER, ALREADY_ACTED, NOT_REVOCABLE
	}

	private final transient Reason reason;

	public JitException(Reason reason, String message) {
		super(message);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
