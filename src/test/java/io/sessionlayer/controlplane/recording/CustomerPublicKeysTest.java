package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class CustomerPublicKeysTest {

	@Test
	void ecP256PublicKeyIsValidForEcies() throws Exception {
		byte[] der = ec().getPublic().getEncoded();
		assertThat(CustomerPublicKeys.isValid(der, "ecies_p256")).isTrue();
		assertThat(CustomerPublicKeys.isValid(der, "rsa_oaep_sha256")).isFalse();
	}

	@Test
	void rsaPublicKeyIsValidForRsaOaep() throws Exception {
		byte[] der = rsa().getPublic().getEncoded();
		assertThat(CustomerPublicKeys.isValid(der, "rsa_oaep_sha256")).isTrue();
		assertThat(CustomerPublicKeys.isValid(der, "ecies_p256")).isFalse();
	}

	@Test
	void aPrivateKeyIsRejected() throws Exception {
		byte[] pkcs8 = ec().getPrivate().getEncoded();
		assertThat(CustomerPublicKeys.isValid(pkcs8, "ecies_p256")).isFalse();
	}

	// secp256k1 and brainpoolP256r1 share P-256's 256-bit field, so a field-size
	// check accepts them -- and the Gateway's sealer, which is P-256 by crate,
	// then refuses every session (strict) or records none of them (strict off).
	@Test
	void aDifferentCurveOnTheSameFieldSizeIsRejected() throws Exception {
		assertThat(CustomerPublicKeys.isValid(namedCurve("secp256k1").getPublic().getEncoded(), "ecies_p256"))
				.isFalse();
		assertThat(CustomerPublicKeys.isValid(namedCurve("brainpoolP256r1").getPublic().getEncoded(), "ecies_p256"))
				.isFalse();
	}

	@Test
	void largerCurvesAreRejected() throws Exception {
		assertThat(CustomerPublicKeys.isValid(namedCurve("secp384r1").getPublic().getEncoded(), "ecies_p256"))
				.isFalse();
		assertThat(CustomerPublicKeys.isValid(namedCurve("secp521r1").getPublic().getEncoded(), "ecies_p256"))
				.isFalse();
	}

	// OAEP-SHA256 cannot wrap a 32-byte data key under a small modulus at all, so
	// a key that passes validation and fails at the first seal is the worst answer.
	@Test
	void anRsaKeyBelowTheModulusFloorIsRejected() throws Exception {
		assertThat(CustomerPublicKeys.isValid(rsaOf(1024).getPublic().getEncoded(), "rsa_oaep_sha256")).isFalse();
	}

	@Test
	void garbageAndEmptyAreRejected() {
		assertThat(CustomerPublicKeys.isValid("not-a-key".getBytes(), "ecies_p256")).isFalse();
		assertThat(CustomerPublicKeys.isValid(new byte[0], "ecies_p256")).isFalse();
		assertThat(CustomerPublicKeys.isValid(null, "ecies_p256")).isFalse();
	}

	private static KeyPair ec() throws Exception {
		return namedCurve("secp256r1");
	}

	// BouncyCastle explicitly, because SunEC cannot GENERATE these curves. It
	// parses them happily -- a secp256k1 or brainpoolP256r1 SPKI comes back from
	// SunEC's KeyFactory as an ECPublicKey with a 256-bit field, which is exactly
	// why a field-size check accepted them and why the named-curve OID check is
	// not redundant.
	private static KeyPair namedCurve(String curve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair();
	}

	private static KeyPair rsa() throws Exception {
		return rsaOf(2048);
	}

	private static KeyPair rsaOf(int bits) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(bits);
		return generator.generateKeyPair();
	}
}
