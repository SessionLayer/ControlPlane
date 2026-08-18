package io.sessionlayer.controlplane.ca.backend;

/**
 * A {@link SignerBackend} could not produce a signature. The interface already
 * requires implementations to throw rather than return a wrong or empty
 * signature; this gives that requirement a type, so the signing path can audit
 * and report a backend failure without knowing which backend failed.
 *
 * <p>
 * Distinct from a missing signer: that means no CA of the kind is usable at
 * all, whereas this means the CA exists, was reached, and refused or
 * misbehaved. The two carry different reasons in the audit trail because they
 * send an operator to different places.
 *
 * <p>
 * Subclasses MUST keep their message free of anything a key service returned -
 * the message reaches error surfaces, the cause does not.
 */
public class CaSigningFailedException extends RuntimeException {

	protected CaSigningFailedException(String message) {
		super(message);
	}

	protected CaSigningFailedException(String message, Throwable cause) {
		super(message, cause);
	}
}
