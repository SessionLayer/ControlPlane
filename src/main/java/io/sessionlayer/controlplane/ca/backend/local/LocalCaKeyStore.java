package io.sessionlayer.controlplane.ca.backend.local;

import io.sessionlayer.controlplane.ca.CaKeyType;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class LocalCaKeyStore {

	private final SecureRandom random;

	public LocalCaKeyStore() {
		this(new SecureRandom());
	}

	public LocalCaKeyStore(SecureRandom random) {
		this.random = random;
	}

	public record GeneratedKey(Kek.Wrapped wrapped, byte[] publicKeyX509, ECPublicKey publicKey) {
	}

	public GeneratedKey generate(CaKeyType keyType, Kek kek, byte[] aad) {
		KeyPair keyPair = generateKeyPair(keyType);
		byte[] pkcs8 = keyPair.getPrivate().getEncoded();
		try {
			Kek.Wrapped wrapped = kek.wrap(pkcs8, aad);
			return new GeneratedKey(wrapped, keyPair.getPublic().getEncoded(), (ECPublicKey) keyPair.getPublic());
		} finally {
			Arrays.fill(pkcs8, (byte) 0);
			destroyQuietly(keyPair.getPrivate());
		}
	}

	public LocalCaBackend load(CaKeyType keyType, Kek kek, Kek.Wrapped wrapped, byte[] publicKeyX509, byte[] aad) {
		byte[] pkcs8 = kek.unwrap(wrapped.iv(), wrapped.ciphertext(), aad);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
			ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));
			return new LocalCaBackend(keyType, privateKey, publicKey);
		} catch (Exception e) {
			throw new IllegalStateException("failed to load local CA key", e);
		} finally {
			Arrays.fill(pkcs8, (byte) 0);
		}
	}

	private static void destroyQuietly(PrivateKey key) {
		try {
			if (key instanceof javax.security.auth.Destroyable d && !d.isDestroyed()) {
				d.destroy();
			}
		} catch (Exception ignored) {
			// Most JCA private keys throw DestroyFailedException (no-op destroy) - the
			// scalar lives in an immutable BigInteger and is reclaimed only by GC; this is
			// inherent to a local software signer (why production SHOULD use
			// KMS/KeyVault/Vault).
		}
	}

	private KeyPair generateKeyPair(CaKeyType keyType) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(keyType.jcaCurve()), random);
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException("failed to generate local CA key for " + keyType.algorithmId(), e);
		}
	}
}
