package io.sessionlayer.controlplane.machine;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.sessionlayer.controlplane.ca.backend.local.Kek;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Signs the machine access tokens {@code POST /v1/oauth2/token} issues.
 *
 * <p>
 * The key is HKDF'd from the operator KEK rather than generated per process. A
 * per-process key is invisible on one replica and breaks the moment there are
 * two: a token minted by one is rejected by the other, so a client on the
 * chart's default {@code replicaCount: 2} sees roughly half its calls answered
 * 401 with nothing in either replica's log. The KEK is already required,
 * already shared by every replica, and already stable across restarts, which is
 * exactly what this key has to be - so tokens now also survive a rolling
 * update.
 *
 * <p>
 * Symmetric on purpose: this Control Plane is the only issuer and the only
 * verifier of these tokens. Nothing outside it validates one, no JWKS is
 * published, and an asymmetric key here would buy a public half nobody reads at
 * the cost of somewhere to keep the private half.
 */
@Component
public class MachineTokenSigner {

	private static final String KEY_INFO = "sessionlayer/machine-token-signing/v1";

	private final MachineTokenProperties properties;
	private final SecretKey key;
	private final MACSigner signer;

	public MachineTokenSigner(MachineTokenProperties properties, KekProvider kekProvider) {
		this.properties = properties;
		Kek kek = kekProvider.newKek();
		byte[] derived = null;
		try {
			derived = kek.derive(KEY_INFO, 32);
			// SecretKeySpec copies, so the array below can be wiped; the signer
			// is built from the copy rather than from the array for that reason.
			this.key = new SecretKeySpec(derived, "HmacSHA256");
			this.signer = new MACSigner(this.key);
		} catch (Exception e) {
			throw new IllegalStateException("failed to initialise the machine-token signing key", e);
		} finally {
			if (derived != null) {
				Arrays.fill(derived, (byte) 0);
			}
			kek.destroy();
		}
	}

	public SecretKey verificationKey() {
		return key;
	}

	public String mint(String identity, List<String> groups) {
		Instant now = Instant.now();
		Instant exp = now.plus(properties.getTokenTtl());
		try {
			JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(properties.getIssuer())
					.audience(properties.getAudience()).subject(identity).claim("groups", groups)
					.claim("token_type", "machine").jwtID(UUID.randomUUID().toString()).issueTime(Date.from(now))
					.notBeforeTime(Date.from(now)).expirationTime(Date.from(exp)).build();
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
					.type(new com.nimbusds.jose.JOSEObjectType("at+jwt")).build();
			SignedJWT jwt = new SignedJWT(header, claims);
			jwt.sign(signer);
			return jwt.serialize();
		} catch (Exception e) {
			throw new IllegalStateException("failed to sign a machine token", e);
		}
	}
}
