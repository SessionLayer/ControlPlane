package io.sessionlayer.controlplane.recording;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public final class CustomerPublicKeys {

	private static final String EC_OID = X9ObjectIdentifiers.id_ecPublicKey.getId();
	private static final String RSA_OID = PKCSObjectIdentifiers.rsaEncryption.getId();

	/** prime256v1. The Gateway's sealer is P-256 only, by crate. */
	private static final String P256_CURVE_OID = X9ObjectIdentifiers.prime256v1.getId();

	/**
	 * OAEP-SHA256 cannot carry a 32-byte data key below this, and 2048 is the floor
	 * anyway.
	 */
	private static final int MIN_RSA_MODULUS_BITS = 2048;

	private CustomerPublicKeys() {
	}

	public static boolean isValid(byte[] der, String sealAlgorithm) {
		if (der == null || der.length == 0) {
			return false;
		}
		try {
			// getInstance over the parsed sequence rejects a PKCS#8 private key (different
			// ASN.1 shape) and any non-SPKI blob before we ever touch a KeyFactory.
			SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(der));
			String oid = spki.getAlgorithm().getAlgorithm().getId();
			X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
			if ("rsa_oaep_sha256".equals(sealAlgorithm)) {
				return RSA_OID.equals(oid)
						&& KeyFactory.getInstance("RSA").generatePublic(spec) instanceof RSAPublicKey rsa
						&& rsa.getModulus().bitLength() >= MIN_RSA_MODULUS_BITS;
			}
			if (!EC_OID.equals(oid)) {
				return false;
			}
			// The NAMED CURVE, not the field size: secp256k1 and brainpoolP256r1 are also
			// 256-bit, and the Gateway's p256 crate cannot parse either. Accepting one here
			// means every session is refused (strict) or unrecorded (strict off) at the
			// first seal, with nothing in the API to explain it.
			if (!isNamedCurve(spki, P256_CURVE_OID)) {
				return false;
			}
			return KeyFactory.getInstance("EC").generatePublic(spec) instanceof ECPublicKey;
		} catch (Exception notAPublicKey) {
			return false;
		}
	}

	private static boolean isNamedCurve(SubjectPublicKeyInfo spki, String curveOid) {
		return spki.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier named
				&& curveOid.equals(named.getId());
	}
}
