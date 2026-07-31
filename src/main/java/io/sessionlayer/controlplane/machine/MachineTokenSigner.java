package io.sessionlayer.controlplane.machine;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Mints and holds the CP's machine-identity token signing key (FR-AUTH-12);
 * regenerated per boot.
 */
@Component
public class MachineTokenSigner {

	private final MachineTokenProperties properties;
	private final KeyPair keyPair;
	private final RSASSASigner signer;

	public MachineTokenSigner(MachineTokenProperties properties) {
		this.properties = properties;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			this.keyPair = generator.generateKeyPair();
			this.signer = new RSASSASigner(keyPair.getPrivate());
		} catch (Exception e) {
			throw new IllegalStateException("failed to initialise the machine-token signing key", e);
		}
	}

	public RSAPublicKey publicKey() {
		return (RSAPublicKey) keyPair.getPublic();
	}

	/**
	 * Sign a machine token binding identity + groups (CPU-bound; run off the event
	 * loop).
	 */
	public String mint(String identity, List<String> groups) {
		Instant now = Instant.now();
		Instant exp = now.plus(properties.getTokenTtl());
		try {
			JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(properties.getIssuer())
					.audience(properties.getAudience()).subject(identity).claim("groups", groups)
					.claim("token_type", "machine").jwtID(UUID.randomUUID().toString()).issueTime(Date.from(now))
					.notBeforeTime(Date.from(now)).expirationTime(Date.from(exp)).build();
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.type(new com.nimbusds.jose.JOSEObjectType("at+jwt")).build();
			SignedJWT jwt = new SignedJWT(header, claims);
			jwt.sign(signer);
			return jwt.serialize();
		} catch (Exception e) {
			throw new IllegalStateException("failed to sign a machine token", e);
		}
	}
}
