package io.sessionlayer.controlplane.node;

/**
 * A fail-closed rejection from {@link NodeLifecycleService}. Carries a
 * {@link Reason} the REST layer maps to an RFC-9457 status
 * ({@code 400}/{@code 404}/{@code 409}/{@code 422}). The message is
 * operator-facing (an admin API); it never reaches the SSH user.
 */
public class NodeRequestException extends RuntimeException {

	public enum Reason {
		INVALID_ARGUMENT, NOT_FOUND, CONFLICT,
		/**
		 * Well-formed request, unusable content - an empty or malformed anchor set on a
		 * host-anchor replace - 422. Distinct from INVALID_ARGUMENT because the anchors
		 * contract states these as {@code 422}.
		 */
		UNPROCESSABLE
	}

	private final Reason reason;

	public NodeRequestException(Reason reason, String message) {
		super(message);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
