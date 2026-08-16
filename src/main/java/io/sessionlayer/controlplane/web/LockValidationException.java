package io.sessionlayer.controlplane.web;

public class LockValidationException extends RuntimeException {

	public LockValidationException(String message) {
		super(message);
	}
}
