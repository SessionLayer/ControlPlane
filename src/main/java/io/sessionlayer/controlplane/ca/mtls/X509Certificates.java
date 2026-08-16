package io.sessionlayer.controlplane.ca.mtls;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Signing uses the JDK's default providers — BouncyCastle is never registered
 * globally with {@code Security.addProvider}, so its algorithms stay scoped to the
 * builders here rather than becoming JVM-wide.
 */
public final class X509Certificates {

	public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

	private X509Certificates() {
	}

	/**
	 * Build a {@code CN=<value>} subject via {@link X500NameBuilder}: the builder
	 * RDN-escapes the value, so a name is never string-concatenated into the DN.
	 * Callers additionally allowlist-validate the value (gateway names, configured
	 * server hostnames).
	 */
	private static X500Name cn(String commonName) {
		return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
	}

	/**
	 * Self-sign an internal CA certificate over {@code caKeyPair}. BasicConstraints
	 * CA=true with pathLen 0 (it signs only leaves), KeyUsage
	 * {@code keyCertSign|cRLSign}, and a Subject Key Identifier.
	 */
	public static X509Certificate selfSignCa(String commonName, PublicKey caPublicKey, PrivateKey caPrivateKey,
			BigInteger serial, Instant notBefore, Instant notAfter) {
		try {
			X500Name subject = cn(commonName);
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, Date.from(notBefore),
					Date.from(notAfter), subject, caPublicKey);
			JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
			builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(caPublicKey));
			ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caPrivateKey);
			return convert(builder.build(signer));
		} catch (Exception e) {
			throw new IllegalStateException("failed to self-sign internal mTLS CA certificate", e);
		}
	}

	public static X509Certificate issueLeaf(X509Certificate caCertificate, PrivateKey caPrivateKey,
			LeafCertificateSpec spec) {
		try {
			X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
			X500Name subject = cn(spec.subjectCommonName());
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, spec.serial(),
					Date.from(spec.notBefore()), Date.from(spec.notAfter()), subject, spec.subjectPublicKey());
			JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
			KeyPurposeId purposeId = switch (spec.purpose()) {
				case SERVER -> KeyPurposeId.id_kp_serverAuth;
				case CLIENT -> KeyPurposeId.id_kp_clientAuth;
				// A data/artifact signer, not a TLS endpoint — the closest standard EKU.
				case CONTEXT_SIGNER -> KeyPurposeId.id_kp_codeSigning;
			};
			builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposeId));
			GeneralNames sans = subjectAlternativeNames(spec);
			if (sans != null) {
				builder.addExtension(Extension.subjectAlternativeName, false, sans);
			}
			builder.addExtension(Extension.subjectKeyIdentifier, false,
					ext.createSubjectKeyIdentifier(spec.subjectPublicKey()));
			builder.addExtension(Extension.authorityKeyIdentifier, false,
					ext.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));
			ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caPrivateKey);
			return convert(builder.build(signer));
		} catch (Exception e) {
			throw new IllegalStateException("failed to issue internal mTLS leaf certificate", e);
		}
	}

	private static GeneralNames subjectAlternativeNames(LeafCertificateSpec spec) {
		List<GeneralName> names = new ArrayList<>();
		for (String dns : spec.dnsSans()) {
			names.add(new GeneralName(GeneralName.dNSName, dns));
		}
		for (String uri : spec.uriSans()) {
			names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
		}
		return names.isEmpty() ? null : new GeneralNames(names.toArray(GeneralName[]::new));
	}

	private static X509Certificate convert(X509CertificateHolder holder) throws Exception {
		return new JcaX509CertificateConverter().getCertificate(holder);
	}

	public static X509Certificate parse(byte[] der) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new java.io.ByteArrayInputStream(der));
		} catch (CertificateException e) {
			throw new IllegalArgumentException("failed to parse X.509 certificate", e);
		}
	}

	/**
	 * Build a PKIX {@link X509TrustManager} anchored on a single CA certificate —
	 * used by the {@code AuthInterceptor} to independently re-validate a presented
	 * client-cert chain against the internal CA (not relying solely on the
	 * TLS-layer toggle, per the trust model in VERSIONING.md §7).
	 */
	public static X509TrustManager trustManagerFor(X509Certificate caCertificate) {
		try {
			KeyStore trust = KeyStore.getInstance("PKCS12");
			trust.load(null, null);
			trust.setCertificateEntry("internal-mtls-ca", caCertificate);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
			tmf.init(trust);
			for (var tm : tmf.getTrustManagers()) {
				if (tm instanceof X509TrustManager x509) {
					return x509;
				}
			}
			throw new IllegalStateException("no X509TrustManager produced for the internal mTLS CA");
		} catch (Exception e) {
			throw new IllegalStateException("failed to build the internal mTLS trust manager", e);
		}
	}
}
