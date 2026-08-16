package io.sessionlayer.controlplane.ca.backend.aws;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;

public final class KmsCaBackend implements SignerBackend {

	private final CaKeyType keyType;
	private final KmsSigner kms;

	public KmsCaBackend(CaKeyType keyType, KmsSigner kms) {
		this.keyType = keyType;
		this.kms = kms;
	}

	@Override
	public CaKeyType keyType() {
		return keyType;
	}

	@Override
	public ECPublicKey publicKey() {
		return kms.publicKey();
	}

	@Override
	public SignerCapabilities capabilities() {
		return SignerCapabilities.of(keyType);
	}

	@Override
	public EcdsaSignatures.RS sign(byte[] toBeSigned) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(toBeSigned);
			return EcdsaSignatures.fromDer(kms.signDigestDer(digest));
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new IllegalStateException("KMS CA signing failed", e);
		}
	}
}
