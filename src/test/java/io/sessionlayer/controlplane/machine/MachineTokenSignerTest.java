package io.sessionlayer.controlplane.machine;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class MachineTokenSignerTest {

	private static final String KEK_A = base64("a-real-32-byte-production-kek!!!");
	private static final String KEK_B = base64("a-different-32-byte-prod-kek!!!!");

	private static String base64(String raw) {
		return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
	}

	private static MachineTokenSigner signerFor(String kekBase64) {
		return new MachineTokenSigner(new MachineTokenProperties(), new KekProvider(kekBase64, null, false));
	}

	private static boolean verifies(MachineTokenSigner verifier, String token) throws Exception {
		return SignedJWT.parse(token).verify(new MACVerifier(verifier.verificationKey()));
	}

	/**
	 * The defect this replaces: the key was generated per process, so a token
	 * minted by one replica failed on the next. Two signers here stand for two
	 * replicas, and for the same replica before and after a restart.
	 */
	@Test
	void aSecondReplicaVerifiesTheFirstReplicasToken() throws Exception {
		MachineTokenSigner first = signerFor(KEK_A);
		MachineTokenSigner second = signerFor(KEK_A);

		String token = first.mint("svc@corp", List.of("platform-admin"));
		assertThat(verifies(second, token)).isTrue();
		assertThat(verifies(first, token)).isTrue();
	}

	@Test
	void aDeploymentWithADifferentKekDoesNotAcceptTheseTokens() throws Exception {
		String token = signerFor(KEK_A).mint("svc@corp", List.of());
		assertThat(verifies(signerFor(KEK_B), token)).isFalse();
	}

	@Test
	void theSigningKeyIsNotTheKekItself() {
		// A key used to wrap CA private keys and to sign bearer tokens is one
		// key whose compromise costs twice; HKDF separates them.
		byte[] kekBytes = "a-real-32-byte-production-kek!!!".getBytes(StandardCharsets.UTF_8);
		byte[] derived = new KekProvider(KEK_A, null, false).newKek().derive("sessionlayer/machine-token-signing/v1",
				32);
		assertThat(derived).hasSize(32).isNotEqualTo(kekBytes);
	}

	@Test
	void theTokenSaysWhatTheResourceServerChecks() throws Exception {
		MachineTokenProperties properties = new MachineTokenProperties();
		String token = signerFor(KEK_A).mint("svc@corp", List.of("platform-admin"));
		SignedJWT jwt = SignedJWT.parse(token);

		assertThat(jwt.getHeader().getType().toString()).isEqualTo("at+jwt");
		assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(properties.getIssuer());
		assertThat(jwt.getJWTClaimsSet().getAudience()).contains(properties.getAudience());
		assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("svc@corp");
		assertThat(jwt.getJWTClaimsSet().getStringListClaim("groups")).containsExactly("platform-admin");
		assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isAfter(jwt.getJWTClaimsSet().getIssueTime());
	}
}
