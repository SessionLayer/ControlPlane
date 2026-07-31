package io.sessionlayer.controlplane.web;

/**
 * Join-token request validation failure. Message is operator-facing (no
 * secrets).
 */
public class JoinTokenValidationException extends RuntimeException {

	public JoinTokenValidationException(String message) {
		super(message);
	}
}
