package io.sessionlayer.controlplane.ca.backend.local;

/**
 * The local-CA KEK in effect is the built-in dev default. Its own type so
 * {@link KekFailureAnalyzer} can turn it into a boxed startup failure: wrapped
 * in Spring's bean-creation chain, the sentence explaining it lands some
 * fifteen hundred characters into an exception message, which is not where an
 * operator reading {@code kubectl logs} on a crash-looping pod finds it.
 */
public class InsecureKekException extends IllegalStateException {

	private static final long serialVersionUID = 1L;

	public InsecureKekException(String message) {
		super(message);
	}
}
