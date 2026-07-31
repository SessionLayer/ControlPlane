package io.sessionlayer.controlplane.ca;

public final class CaBackendCapabilities {

	private CaBackendCapabilities() {
	}

	public static final class AlgorithmNotSupported extends RuntimeException {
		public AlgorithmNotSupported(String backend, String algorithm) {
			super("CA backend '" + backend + "' cannot produce algorithm '" + algorithm
					+ "' (SessionLayer signs ECDSA P-256/P-384/P-521)");
		}
	}

	public static final class BackendNotImplemented extends RuntimeException {
		public BackendNotImplemented(String backend) {
			super("CA backend '" + backend + "' has no signer in this build: it is a key-service integration seam"
					+ " whose implementation is supplied by the deployment, so a CA configured this way would accept"
					+ " the write and then fail every signature — no session or host certificate could be issued."
					+ " 'local' and 'azure_keyvault' are the backends that sign as shipped; protect 'local' with a"
					+ " real KEK and 'azure_keyvault' with sessionlayer.ca.azure.* configured.");
		}
	}

	public static SignerCapabilities forBackend(String backend) {
		return switch (backend) {
			case "local" ->
				SignerCapabilities.of(CaKeyType.ECDSA_NISTP256, CaKeyType.ECDSA_NISTP384, CaKeyType.ECDSA_NISTP521);
			case "aws_kms", "azure_keyvault", "vault" -> SignerCapabilities.of(CaKeyType.ECDSA_NISTP256);
			default -> throw new IllegalArgumentException("unknown CA backend: " + backend);
		};
	}

	/**
	 * Whether a backend can actually produce a signer in THIS build — the question
	 * {@code CaSignerService.signerFor} asks, asked once so the two cannot diverge.
	 *
	 * <p>
	 * Deliberately not "does a backend class exist". {@code aws_kms} and
	 * {@code vault} have classes ({@code KmsCaBackend}, {@code VaultCaCertSigner})
	 * and neither has an implementation of the interface it consumes, no bean
	 * constructs either, and {@code signerFor} refuses both before per-backend
	 * dispatch is reached. {@code azure_keyvault} is the one key-service seam with
	 * a real, bean-backed implementation ({@code AzureKeyVaultSignerFactory}, gated
	 * on {@code sessionlayer.ca.azure.enabled}) — a build that has it on the
	 * classpath can sign, a deployment that has not configured a vault still fails
	 * closed at {@code signerFor}, which is a deployment question, not a build one.
	 * A first pass at this method answered the class-existence question and
	 * reported two of the three as usable — the same mistake as
	 * {@link #forBackend}, which is truthful about algorithms and silent about
	 * signers.
	 */
	public static boolean isImplemented(String backend) {
		return switch (backend) {
			case "local", "azure_keyvault" -> true;
			case "aws_kms", "vault" -> false;
			default -> throw new IllegalArgumentException("unknown CA backend: " + backend);
		};
	}

	/**
	 * Write-path gate only. The contract enum and the {@code ca_config} CHECK stay
	 * wider on purpose, so a row an older deployment already holds is still
	 * readable; this is what stops a new one being written.
	 */
	public static void validate(String backend, String algorithm) {
		if (!isImplemented(backend)) {
			throw new BackendNotImplemented(backend);
		}
		if (!forBackend(backend).supports(algorithm)) {
			throw new AlgorithmNotSupported(backend, algorithm);
		}
	}
}
