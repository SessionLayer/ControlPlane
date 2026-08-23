package io.sessionlayer.controlplane.machine;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

final class ClientAssertions {

	private ClientAssertions() {
	}

	record Claims(String issuer, String subject, String jti, Instant expiresAt, List<String> audience) {
	}

	static Claims parseUnverified(String assertion) {
		try {
			var set = SignedJWT.parse(assertion).getJWTClaimsSet();
			Instant exp = set.getExpirationTime() == null ? null : set.getExpirationTime().toInstant();
			return new Claims(set.getIssuer(), set.getSubject(), set.getJWTID(), exp,
					set.getAudience() == null ? List.of() : set.getAudience());
		} catch (Exception malformed) {
			return null;
		}
	}

	static boolean verify(String assertion, PublicKey key) {
		try {
			SignedJWT jwt = SignedJWT.parse(assertion);
			JWSVerifier verifier = switch (key) {
				case RSAPublicKey rsa -> new RSASSAVerifier(rsa);
				case ECPublicKey ec -> new ECDSAVerifier(ec);
				default -> null;
			};
			return verifier != null && jwt.verify(verifier);
		} catch (Exception invalid) {
			return false;
		}
	}
}
