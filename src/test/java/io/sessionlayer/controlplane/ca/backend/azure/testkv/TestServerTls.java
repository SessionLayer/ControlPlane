package io.sessionlayer.controlplane.ca.backend.azure.testkv;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A throwaway self-signed TLS server identity for {@link KeyVaultRestDouble},
 * built with BouncyCastle the same way {@code ca.mtls.X509Certificates} does.
 * Distinct from that helper: this is a leaf (not a CA), EKU {@code serverAuth},
 * and carries both a {@code dNSName=localhost} and an
 * {@code iPAddress=127.0.0.1} SAN — JSSE's HTTPS endpoint-identification
 * algorithm matches an IP-literal hostname only against an iPAddress SAN, so a
 * dNSName SAN alone would fail the exact "127.0.0.1" URL the double is
 * addressed by.
 */
final class TestServerTls {

	private TestServerTls() {
	}

	record Identity(SSLContext serverContext, X509Certificate certificate) {
	}

	static Identity generate() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			KeyPair pair = generator.generateKeyPair();

			Instant now = Instant.now();
			X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "keyvault-rest-double").build();
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject,
					BigInteger.valueOf(System.nanoTime()), Date.from(now.minus(Duration.ofHours(1))),
					Date.from(now.plus(Duration.ofHours(1))), subject, pair.getPublic());
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
			builder.addExtension(Extension.extendedKeyUsage, false,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			builder.addExtension(Extension.subjectAlternativeName, false,
					new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, "localhost"),
							new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
			ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate());
			X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			keyStore.setKeyEntry("server", pair.getPrivate(), new char[0], new X509Certificate[]{certificate});
			KeyManagerFactory keyManagerFactory = KeyManagerFactory
					.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, new char[0]);

			SSLContext serverContext = SSLContext.getInstance("TLSv1.3");
			serverContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
			return new Identity(serverContext, certificate);
		} catch (Exception e) {
			throw new IllegalStateException("failed to build the Key Vault double's TLS identity", e);
		}
	}
}
