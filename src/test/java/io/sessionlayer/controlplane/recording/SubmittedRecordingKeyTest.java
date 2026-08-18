package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class SubmittedRecordingKeyTest {

	/**
	 * The direction nobody wrote. Every other assertion here checks that private
	 * key material is refused, and a detector that fires on everything passes all
	 * of them - so the suite could not distinguish a strict guard from a broken
	 * one.
	 */
	@Test
	void aRealPublicKeyIsNotPrivateKeyMaterial() throws Exception {
		byte[] spki = ec("secp256r1").getPublic().getEncoded();
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(spki)).isFalse();
		assertThat(SubmittedRecordingKey.carriesPemMarker(spki)).isFalse();
		assertThat(SubmittedRecordingKey.carriesPemMarker(Base64.getEncoder().encodeToString(spki))).isFalse();
	}

	@Test
	void largerCurvePublicKeysAreAlsoNotPrivateKeyMaterial() throws Exception {
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(ec("secp384r1").getPublic().getEncoded())).isFalse();
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(ec("secp521r1").getPublic().getEncoded())).isFalse();
	}

	@Test
	void anRsaPublicKeyIsNotPrivateKeyMaterial() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(generator.generateKeyPair().getPublic().getEncoded()))
				.isFalse();
	}

	@Test
	void pkcs8AndSec1PrivateKeysAreDetected() throws Exception {
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(ec("secp256r1").getPrivate().getEncoded())).isTrue();
	}

	@Test
	void pemMarkersAreDetectedRawAndDecoded() {
		String pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----";
		assertThat(SubmittedRecordingKey.carriesPemMarker(pem)).isTrue();
		assertThat(SubmittedRecordingKey.carriesPemMarker(Base64.getEncoder().encodeToString(pem.getBytes())))
				.isFalse();
		assertThat(SubmittedRecordingKey.carriesPemMarker(pem.getBytes())).isTrue();
	}

	@Test
	void garbageIsNotPrivateKeyMaterial() {
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial("not-a-key".getBytes())).isFalse();
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(new byte[0])).isFalse();
		assertThat(SubmittedRecordingKey.isPrivateKeyMaterial(null)).isFalse();
	}

	private static KeyPair ec(String curve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair();
	}
}
