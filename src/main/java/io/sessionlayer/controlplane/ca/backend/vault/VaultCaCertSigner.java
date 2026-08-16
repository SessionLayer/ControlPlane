package io.sessionlayer.controlplane.ca.backend.vault;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SignerCapabilities;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

public final class VaultCaCertSigner implements SshCertSigner {

	private final CaKeyType keyType;
	private final VaultSshEngine engine;
	private final String role;

	public VaultCaCertSigner(CaKeyType keyType, VaultSshEngine engine, String role) {
		this.keyType = keyType;
		this.engine = engine;
		this.role = role;
	}

	@Override
	public CaKeyType keyType() {
		return keyType;
	}

	@Override
	public byte[] caPublicKeyBlob() {
		return SshEcdsaPublicKeys.encode(SshEcdsaPublicKeys.parseAuthorizedKey(engine.caPublicKeyLine()), keyType);
	}

	@Override
	public String caAuthorizedKey(String comment) {
		String line = engine.caPublicKeyLine().trim();
		return (comment == null || comment.isBlank()) ? line : line + " " + comment;
	}

	@Override
	public SignerCapabilities capabilities() {
		return SignerCapabilities.of(keyType);
	}

	@Override
	public OpenSshCertificate signCertificate(CertificateRequest request) {
		CertificateParameters params = request.parameters();
		String subjectLine = SshEcdsaPublicKeys.toAuthorizedKey(request.subjectPublicKey(), keyType, params.keyId());
		long ttlSeconds = Math.max(1, Duration.between(Instant.now(), params.validBefore()).getSeconds());
		VaultSshEngine.SignRequest signRequest = new VaultSshEngine.SignRequest(params.keyId(),
				java.util.List.copyOf(params.principals()), ttlSeconds, params.criticalOptions(),
				java.util.List.copyOf(params.extensions()));
		String certLine = engine.sign(role, subjectLine, signRequest).certificateLine();
		byte[] blob = Base64.getDecoder().decode(certLine.trim().split("\\s+")[1]);
		// Vault assigns its OWN serial (it ignores the requested one), so surface the
		// serial actually in the returned blob for correct audit correlation, not the
		// requested value. Best-effort: fall back to the requested serial
		// if
		// the blob cannot be parsed.
		long serial = serialOf(blob).orElse(params.serial());
		return new OpenSshCertificate(keyType, blob, certLine, serial, params.keyId());
	}

	private static java.util.OptionalLong serialOf(byte[] blob) {
		try {
			var r = new io.sessionlayer.controlplane.ca.wire.SshReader(blob);
			r.readString(); // cert-type
			r.readString(); // nonce
			r.readString(); // curve
			r.readString(); // Q
			return java.util.OptionalLong.of(r.readUint64());
		} catch (RuntimeException e) {
			return java.util.OptionalLong.empty();
		}
	}

	@Override
	public EcdsaSignatures.RS rawSign(byte[] toBeSigned) {
		throw new UnsupportedOperationException(
				"Vault SSH engine returns a signed certificate directly; it exposes no raw-sign primitive");
	}
}
