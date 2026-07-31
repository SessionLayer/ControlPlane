package io.sessionlayer.controlplane.web;

/**
 * Lock create request validation failure. Message is operator-facing (no
 * secrets).
 */
public class LockValidationException extends RuntimeException {

	public LockValidationException(String message) {
		super(message);
	}
}
