package io.sessionlayer.controlplane.recording;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/**
 * Guards the one submission this endpoint most owes a clear answer to: an
 * operator pasting the PRIVATE half of the customer recording key.
 *
 * <p>
 * {@link CustomerPublicKeys#isValid} would already refuse it — a PKCS#8
 * {@code PrivateKeyInfo} is not an SPKI — but only as "not a valid public key",
 * which does not tell an operator that they have just put private key material
 * on the wire. These checks run first so the error can name it.
 */
public final class SubmittedRecordingKey {

	private static final String PEM_PRIVATE_MARKER = "PRIVATE KEY";
	private static final String PEM_BEGIN_MARKER = "BEGIN ";

	private SubmittedRecordingKey() {
	}

	/**
	 * True if the text carries a PEM marker — checked on the raw submission and
	 * again on the decoded bytes, since base64 of a PEM block decodes to the PEM
	 * text itself.
	 */
	public static boolean carriesPemMarker(String text) {
		if (text == null) {
			return false;
		}
		String upper = text.toUpperCase(java.util.Locale.ROOT);
		return upper.contains(PEM_PRIVATE_MARKER) || upper.contains(PEM_BEGIN_MARKER);
	}

	public static boolean carriesPemMarker(byte[] decoded) {
		return decoded != null && carriesPemMarker(new String(decoded, StandardCharsets.ISO_8859_1));
	}

	public static boolean isPrivateKeyMaterial(byte[] der) {
		if (der == null || der.length == 0) {
			return false;
		}
		ASN1Sequence sequence;
		try {
			sequence = ASN1Sequence.getInstance(der);
		} catch (RuntimeException notASequence) {
			return false;
		}
		try {
			PrivateKeyInfo.getInstance(sequence);
			return true;
		} catch (RuntimeException notPkcs8) {
			// fall through to SEC1
		}
		return isSec1EcPrivateKey(sequence);
	}

	/**
	 * SEC1 {@code ECPrivateKey} is
	 * {@code SEQUENCE { INTEGER 1, OCTET STRING, ... }} and is matched structurally
	 * rather than by handing the sequence to a parser.
	 * {@code ECPrivateKey.getInstance} accepts a well-formed SubjectPublicKeyInfo —
	 * it reads the members positionally without checking their types — so using it
	 * here refused every legitimate public key with the message reserved for the
	 * one mistake this guard exists to name.
	 */
	private static boolean isSec1EcPrivateKey(ASN1Sequence sequence) {
		return sequence.size() >= 2 && sequence.getObjectAt(0) instanceof ASN1Integer version
				&& version.getValue().intValueExact() == 1 && sequence.getObjectAt(1) instanceof ASN1OctetString;
	}

	public static String fingerprintSha256(byte[] der) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
		} catch (java.security.NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 unavailable", impossible);
		}
	}
}
