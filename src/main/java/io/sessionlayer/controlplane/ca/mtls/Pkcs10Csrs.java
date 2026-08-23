package io.sessionlayer.controlplane.ca.mtls;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Parses and validates a PKCS#10 {@code CertificationRequest} (the Gateway's
 * CSR) on the trust boundary. Fail-closed at every step:
 *
 * <ul>
 * <li><b>Proof of possession</b> - the CSR self-signature is verified against
 * the embedded public key, so a CSR cannot claim a key the requester does not
 * hold.</li>
 * <li><b>Key type</b> - ECDSA with a 256-bit field is required. Note this is a
 * field-size check, not a curve check: another 256-bit curve (secp256k1,
 * brainpoolP256r1) passes here, unlike {@code recording.CustomerPublicKeys},
 * which compares the named-curve OID.</li>
 * <li><b>Subject</b> - the CN is extracted for the caller to check against the
 * enrollment scope / current identity.</li>
 * </ul>
 *
 * The CP receives only the CSR (public key + PoP) and returns a certificate;
 * the private key never leaves the Gateway.
 */
public final class Pkcs10Csrs {

	private static final int P256_FIELD_BITS = 256;

	private Pkcs10Csrs() {
	}

	public record ParsedCsr(PublicKey publicKey, String commonName) {
	}

	public static ParsedCsr parseAndVerify(byte[] der) {
		if (der == null || der.length == 0) {
			throw new CsrException("empty CSR");
		}
		try {
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
			ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
					.build(csr.getSubjectPublicKeyInfo());
			if (!csr.isSignatureValid(verifier)) {
				throw new CsrException("CSR proof-of-possession signature is invalid");
			}
			PublicKey publicKey = KeyFactory.getInstance("EC")
					.generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().getEncoded()));
			requireP256(publicKey);
			return new ParsedCsr(publicKey, commonName(csr.getSubject()));
		} catch (CsrException e) {
			throw e;
		} catch (Exception e) {
			throw new CsrException("failed to parse/validate PKCS#10 CSR", e);
		}
	}

	private static void requireP256(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey ec)) {
			throw new CsrException("CSR public key is not ECDSA (only ECDSA P-256 is accepted)");
		}
		int fieldBits = ec.getParams().getCurve().getField().getFieldSize();
		if (fieldBits != P256_FIELD_BITS) {
			throw new CsrException("CSR key curve is " + fieldBits + "-bit; only ECDSA P-256 is accepted");
		}
	}

	private static String commonName(X500Name subject) {
		RDN[] cns = subject.getRDNs(BCStyle.CN);
		if (cns.length == 0) {
			throw new CsrException("CSR subject has no CN");
		}
		String cn = IETFUtils.valueToString(cns[0].getFirst().getValue());
		if (cn == null || cn.isBlank()) {
			throw new CsrException("CSR subject CN is blank");
		}
		return cn;
	}

	public static final class CsrException extends RuntimeException {
		public CsrException(String message) {
			super(message);
		}

		public CsrException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
