package io.sessionlayer.controlplane.ca.key;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class SshEcdsaPublicKeys {

	private SshEcdsaPublicKeys() {
	}

	public static byte[] encode(ECPublicKey publicKey, CaKeyType keyType) {
		return new SshWriter().writeString(keyType.keyTypeName()).writeBytes(encodeCurveAndPoint(publicKey, keyType))
				.toByteArray();
	}

	public static byte[] encodeCurveAndPoint(ECPublicKey publicKey, CaKeyType keyType) {
		int coordLen = keyType.coordinateBytes();
		byte[] x = fixedWidth(publicKey.getW().getAffineX(), coordLen);
		byte[] y = fixedWidth(publicKey.getW().getAffineY(), coordLen);
		byte[] q = new byte[1 + x.length + y.length];
		q[0] = 0x04; // uncompressed point
		System.arraycopy(x, 0, q, 1, x.length);
		System.arraycopy(y, 0, q, 1 + x.length, y.length);
		return new SshWriter().writeString(keyType.curveName()).writeString(q).toByteArray();
	}

	public static String toAuthorizedKey(ECPublicKey publicKey, CaKeyType keyType, String comment) {
		String b64 = Base64.getEncoder().encodeToString(encode(publicKey, keyType));
		return keyType.keyTypeName() + " " + b64 + (comment == null || comment.isBlank() ? "" : " " + comment);
	}

	/**
	 * The OpenSSH {@code SHA256:...} fingerprint of a public-key wire blob, as
	 * {@code ssh-keygen -l} prints it: base64 without padding over SHA-256 of the
	 * exact wire bytes.
	 */
	public static String fingerprint(byte[] blob) {
		try {
			byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(blob);
			return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
		} catch (java.security.NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 unavailable", impossible);
		}
	}

	public static ECPublicKey parse(byte[] blob) {
		try {
			SshReader reader = new SshReader(blob);
			CaKeyType keyType = CaKeyType.fromKeyTypeName(reader.readStringUtf8());
			String curve = reader.readStringUtf8();
			if (!keyType.curveName().equals(curve)) {
				throw new IllegalArgumentException(
						"curve '" + curve + "' does not match key type " + keyType.keyTypeName());
			}
			byte[] q = reader.readString();
			int coordLen = keyType.coordinateBytes();
			if (q.length != 1 + 2 * coordLen || q[0] != 0x04) {
				throw new IllegalArgumentException("expected uncompressed EC point (0x04||X||Y)");
			}
			BigInteger x = new BigInteger(1, Arrays.copyOfRange(q, 1, 1 + coordLen));
			BigInteger y = new BigInteger(1, Arrays.copyOfRange(q, 1 + coordLen, 1 + 2 * coordLen));
			AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
			params.init(new java.security.spec.ECGenParameterSpec(keyType.jcaCurve()));
			ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
			ECPoint point = new ECPoint(x, y);
			requireOnCurve(point, spec);
			return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
		} catch (Exception e) {
			throw new IllegalArgumentException("failed to parse SSH ECDSA public key", e);
		}
	}

	/**
	 * Reject a point not on the curve (defense at the presented-key trust
	 * boundary).
	 */
	static void requireOnCurve(ECPoint point, ECParameterSpec spec) {
		if (point.equals(ECPoint.POINT_INFINITY)) {
			throw new IllegalArgumentException("EC point is the point at infinity");
		}
		java.security.spec.EllipticCurve curve = spec.getCurve();
		BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
		BigInteger x = point.getAffineX();
		BigInteger y = point.getAffineY();
		if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
			throw new IllegalArgumentException("EC coordinate out of field range");
		}
		BigInteger lhs = y.modPow(BigInteger.TWO, p);
		BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
		if (!lhs.equals(rhs)) {
			throw new IllegalArgumentException("EC point is not on the curve");
		}
	}

	/** Parse an OpenSSH {@code "<type> <base64> [comment]"} public-key line. */
	public static ECPublicKey parseAuthorizedKey(String line) {
		String[] parts = line.trim().split("\\s+");
		if (parts.length < 2) {
			throw new IllegalArgumentException("not an OpenSSH public-key line");
		}
		return parse(Base64.getDecoder().decode(parts[1]));
	}

	/**
	 * Big-endian fixed-width encoding of a non-negative integer: strips
	 * {@link BigInteger#toByteArray()}'s sign byte and left-pads with zeros to
	 * {@code length}. Rejects a value too wide for the coordinate size.
	 */
	static byte[] fixedWidth(BigInteger value, int length) {
		byte[] raw = value.toByteArray();
		// Drop a leading 0x00 sign byte if present.
		int start = 0;
		if (raw.length > 1 && raw[0] == 0x00) {
			start = 1;
		}
		int len = raw.length - start;
		if (len > length) {
			throw new IllegalArgumentException("coordinate too wide (" + len + " > " + length + " bytes)");
		}
		byte[] out = new byte[length];
		System.arraycopy(raw, start, out, length - len, len);
		return out;
	}
}
