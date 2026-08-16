package io.sessionlayer.controlplane.ca.mtls;

/**
 * The role of an issued X.509 leaf certificate on the internal mTLS plane,
 * which fixes its Extended Key Usage: the CP's own gRPC server certificate
 * ({@code serverAuth}), a Gateway's client identity certificate
 * ({@code clientAuth}), or the decision-context signer ({@code codeSigning}).
 * Default-deny: exactly one EKU is stamped per leaf.
 */
public enum LeafPurpose {

	/**
	 * A TLS server certificate (EKU serverAuth): the CP's own gRPC server
	 * certificate, and a Gateway's agent-facing listener certificate. A Gateway's
	 * {@link #CLIENT} identity leaf cannot serve TLS (one EKU per leaf), so it gets
	 * a separate serverAuth leaf, over a separate keypair, from this same CA — the
	 * anchor Agents already hold, so they never trust it on first use.
	 */
	SERVER,

	CLIENT,

	CONTEXT_SIGNER
}
