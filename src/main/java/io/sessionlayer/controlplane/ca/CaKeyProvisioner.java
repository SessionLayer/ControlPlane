package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;

/**
 * Provisions (or adopts) a CA key for one {@code ca_config.backend} value.
 * {@link CaRotationService} selects an implementation by {@link #backend()}
 * rather than branching on the backend string itself, so a key-service backend
 * (Azure Key Vault, KMS, Vault) is a new implementation of this seam, not a new
 * case in rotation's own logic.
 */
public interface CaKeyProvisioner {

	/** The {@code ca_config.backend} value this provisions for. */
	String backend();

	/**
	 * Provision (or adopt) a CA key for a kind. Must throw rather than return a
	 * partial result — the caller persists {@code config()}/{@code material()}
	 * together in one transaction, so a partial {@link Provisioned} would still
	 * fail closed on write, but throwing here fails closed before either row is
	 * even built.
	 */
	Provisioned provision(Request request);

	record Request(String caKind, String caName, String rotationState, String keyReference, String algorithm) {
	}

	record Provisioned(CaConfig config, CaKeyMaterial material) {
	}
}
