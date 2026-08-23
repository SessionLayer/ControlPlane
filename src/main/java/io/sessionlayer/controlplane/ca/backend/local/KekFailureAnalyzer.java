package io.sessionlayer.controlplane.ca.backend.local;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Prints the dev-KEK refusal as Spring Boot's APPLICATION FAILED TO START
 * block, which is the last thing on stdout before the process exits and so the
 * first thing {@code kubectl logs --tail} shows.
 *
 * <p>
 * The action names the environment variable as well as the property: an
 * operator sets this through a Kubernetes Secret key, and a message that names
 * only {@code sessionlayer.ca.local.kek-base64} does not tell them which key of
 * theirs is wrong.
 */
public class KekFailureAnalyzer extends AbstractFailureAnalyzer<InsecureKekException> {

	@Override
	protected FailureAnalysis analyze(Throwable rootFailure, InsecureKekException cause) {
		return new FailureAnalysis("""
				The local certificate authority's key-encryption key (KEK) is the built-in \
				development default. That value is a public constant in this project's source, \
				so every CA private key wrapped under it is readable by anyone who reads the \
				database.""", """
				Set the KEK to 32 random bytes, base64-encoded:

				    head -c 32 /dev/urandom | base64 -w0

				and supply it as SESSIONLAYER_CA_LOCAL_KEK_BASE64 in the environment (the Helm \
				chart takes it from the Secret named by secrets.existingSecret), or as the \
				property sessionlayer.ca.local.kek-base64.

				The KEK must be stable across restarts: the same value has to unwrap the CA \
				keys it wrapped, so keep it in a durable secret rather than regenerating it \
				per deploy.

				For development and tests only, SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK=true \
				accepts the default deliberately. Never set it in production.""", cause);
	}
}
