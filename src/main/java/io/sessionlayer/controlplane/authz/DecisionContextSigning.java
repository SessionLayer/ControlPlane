package io.sessionlayer.controlplane.authz;

import java.nio.charset.StandardCharsets;

public final class DecisionContextSigning {

	public static final byte[] DOMAIN_PREFIX = "sessionlayer:decision-context:v1\n".getBytes(StandardCharsets.UTF_8);

	public static final String SIGNER_URI = "sessionlayer://decision-context-signer";

	public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

	private DecisionContextSigning() {
	}
}
