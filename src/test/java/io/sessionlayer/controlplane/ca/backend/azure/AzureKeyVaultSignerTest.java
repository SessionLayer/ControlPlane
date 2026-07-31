package io.sessionlayer.controlplane.ca.backend.azure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSigner.KeyVaultSigningException;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * Mockito 5's default inline mock maker mocks {@code CryptographyClient}
 * directly (a final SDK class with package-private constructors) — verified
 * here rather than introducing a second seam interface duplicating
 * {@link KeyVaultSigner}.
 */
class AzureKeyVaultSignerTest {

	private static final String KEY_REF = "https://myvault.vault.azure.net/keys/ssh-ca/v1";

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return g.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] digest32() {
		byte[] d = new byte[32];
		new SecureRandom().nextBytes(d);
		return d;
	}

	private static byte[] derSignatureBy(PrivateKey key, byte[] digest) throws Exception {
		Signature s = Signature.getInstance("NONEwithECDSA");
		s.initSign(key);
		s.update(digest);
		return s.sign();
	}

	/**
	 * Emulates what Key Vault returns for {@code ES256}: fixed-width {@code r||s}.
	 */
	private static byte[] p1363SignatureBy(PrivateKey key, byte[] digest) throws Exception {
		EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(derSignatureBy(key, digest));
		byte[] out = new byte[64];
		writeFixed(rs.r(), out, 0);
		writeFixed(rs.s(), out, 32);
		return out;
	}

	private static void writeFixed(BigInteger value, byte[] out, int offset) {
		byte[] raw = value.toByteArray();
		int start = Math.max(0, raw.length - 32);
		int len = raw.length - start;
		System.arraycopy(raw, start, out, offset + (32 - len), len);
	}

	@Test
	void signsAndReturnsTheVerifiedP1363Signature() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		byte[] expected = p1363SignatureBy(ca.getPrivate(), digest);

		CryptographyClient client = mock(CryptographyClient.class);
		when(client.sign(SignatureAlgorithm.ES256, digest))
				.thenReturn(new SignResult(expected, SignatureAlgorithm.ES256, KEY_REF));

		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(client, (ECPublicKey) ca.getPublic(), KEY_REF);

		assertThat(signer.signDigestP1363(digest)).isEqualTo(expected);
	}

	@Test
	void rejectsADigestThatIsNotExactly32Bytes() {
		CryptographyClient client = mock(CryptographyClient.class);
		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(client, (ECPublicKey) ecKeyPair().getPublic(), KEY_REF);

		assertThatThrownBy(() -> signer.signDigestP1363(new byte[10])).isInstanceOf(KeyVaultSigningException.class)
				.hasMessageContaining("32 bytes");
	}

	/** Pinning is enforced here, not merely documented. */
	@Test
	void aSignatureMadeByADifferentKeyFailsTheLocalVerificationGuard() throws Exception {
		KeyPair pinned = ecKeyPair();
		KeyPair impostor = ecKeyPair();
		byte[] digest = digest32();
		byte[] wrongKeySignature = p1363SignatureBy(impostor.getPrivate(), digest);

		CryptographyClient client = mock(CryptographyClient.class);
		when(client.sign(SignatureAlgorithm.ES256, digest))
				.thenReturn(new SignResult(wrongKeySignature, SignatureAlgorithm.ES256, KEY_REF));

		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(client, (ECPublicKey) pinned.getPublic(), KEY_REF);

		assertThatThrownBy(() -> signer.signDigestP1363(digest)).isInstanceOf(KeyVaultSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	/**
	 * C.2: a DER-shaped signature in the P1363 position must fail — a test that
	 * passes on either shape proves the normalization is not load-bearing.
	 */
	@Test
	void aDerShapedSignatureInTheP1363PositionFails() throws Exception {
		KeyPair ca = ecKeyPair();
		byte[] digest = digest32();
		byte[] der = derSignatureBy(ca.getPrivate(), digest);

		CryptographyClient client = mock(CryptographyClient.class);
		when(client.sign(SignatureAlgorithm.ES256, digest))
				.thenReturn(new SignResult(der, SignatureAlgorithm.ES256, KEY_REF));

		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(client, (ECPublicKey) ca.getPublic(), KEY_REF);

		assertThatThrownBy(() -> signer.signDigestP1363(digest)).isInstanceOf(KeyVaultSigningException.class)
				.hasMessageContaining("does not verify against the pinned public key");
	}

	/** The seam's own message never forwards the SDK exception's own detail. */
	@Test
	void aVaultFailureIsWrappedWithoutTheUnderlyingMessage() {
		CryptographyClient client = mock(CryptographyClient.class);
		byte[] digest = digest32();
		when(client.sign(SignatureAlgorithm.ES256, digest))
				.thenThrow(new RuntimeException("secret vault response body"));

		AzureKeyVaultSigner signer = new AzureKeyVaultSigner(client, (ECPublicKey) ecKeyPair().getPublic(), KEY_REF);

		assertThatThrownBy(() -> signer.signDigestP1363(digest)).isInstanceOf(KeyVaultSigningException.class)
				.hasMessageContaining(KEY_REF).hasMessageContaining("RuntimeException")
				.hasMessageNotContaining("secret vault response body");
	}
}
