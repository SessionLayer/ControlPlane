package io.sessionlayer.controlplane.ca.cert;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class OpenSshCertificateAssembler {

	private final SecureRandom random;

	public OpenSshCertificateAssembler() {
		this(new SecureRandom());
	}

	public OpenSshCertificateAssembler(SecureRandom random) {
		this.random = random;
	}

	public byte[] newNonce() {
		byte[] nonce = new byte[32];
		random.nextBytes(nonce);
		return nonce;
	}

	public byte[] buildToBeSigned(CaKeyType keyType, byte[] nonce, byte[] certifiedKeyBody,
			CertificateParameters params, byte[] caPublicKeyBlob) {
		SshWriter w = new SshWriter();
		w.writeString(keyType.certTypeName());
		w.writeString(nonce);
		w.writeBytes(certifiedKeyBody); // string(curve) || string(Q)
		w.writeUint64(params.serial());
		w.writeUint32(params.type().value());
		w.writeString(params.keyId());
		w.writeString(encodePrincipals(params));
		w.writeUint64(epochSeconds(params.validAfter()));
		w.writeUint64(epochSeconds(params.validBefore()));
		w.writeString(encodeCriticalOptions(params));
		w.writeString(encodeExtensions(params));
		w.writeString(new byte[0]); // reserved
		w.writeString(caPublicKeyBlob);
		return w.toByteArray();
	}

	public byte[] assembleSigned(byte[] toBeSigned, byte[] signatureField) {
		return new SshWriter().writeBytes(toBeSigned).writeString(signatureField).toByteArray();
	}

	public String toCertificateLine(CaKeyType keyType, byte[] certificateBlob, String comment) {
		String b64 = Base64.getEncoder().encodeToString(certificateBlob);
		return keyType.certTypeName() + " " + b64 + (comment == null || comment.isBlank() ? "" : " " + comment);
	}

	private static byte[] encodePrincipals(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (String p : params.principals()) {
			w.writeString(p);
		}
		return w.toByteArray();
	}

	private static byte[] encodeCriticalOptions(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (Map.Entry<String, String> e : params.criticalOptions().entrySet()) {
			w.writeString(e.getKey());
			w.writeString(new SshWriter().writeString(e.getValue()).toByteArray());
		}
		return w.toByteArray();
	}

	// extensions: sorted (name, empty) - a flag's data is a zero-length string
	// (still
	// its 4-byte length prefix). Distinguishing this from a value option is THE
	// bug.
	private static byte[] encodeExtensions(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (String name : params.extensions()) {
			w.writeString(name);
			w.writeString(new byte[0]);
		}
		return w.toByteArray();
	}

	private static long epochSeconds(java.time.Instant instant) {
		return instant.getEpochSecond();
	}
}
