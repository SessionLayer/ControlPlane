package io.sessionlayer.controlplane.mtls;

import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public final class MtlsTestSupport {

	private MtlsTestSupport() {
	}

	public static KeyPair generateEcKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static byte[] csr(KeyPair keyPair, String commonName) {
		try {
			var subject = new org.bouncycastle.asn1.x500.X500Name("CN=" + commonName);
			var builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
			ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
			return builder.build(signer).getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build test CSR", e);
		}
	}

	public static byte[] csrRequestingSans(KeyPair keyPair, String commonName, List<String> dnsSans) {
		try {
			var subject = new org.bouncycastle.asn1.x500.X500Name("CN=" + commonName);
			var builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
			GeneralName[] requested = dnsSans.stream().map(dns -> new GeneralName(GeneralName.dNSName, dns))
					.toArray(GeneralName[]::new);
			ExtensionsGenerator extensions = new ExtensionsGenerator();
			extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(requested));
			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
			ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
			return builder.build(signer).getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build test CSR with requested SANs", e);
		}
	}

	public static byte[] opensshPublicKeyBlob(ECPublicKey publicKey) {
		return SshEcdsaPublicKeys.encode(publicKey, CaKeyType.ECDSA_NISTP256);
	}

	public static SslContext clientSslContext(X509Certificate caCertificate, X509Certificate clientLeaf,
			PrivateKey clientKey) {
		try {
			SslContextBuilder builder = GrpcSslContexts.forClient().trustManager(caCertificate);
			builder.protocols("TLSv1.3");
			if (clientLeaf != null && clientKey != null) {
				builder.keyManager(clientKey, clientLeaf);
			}
			return builder.build();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build client SslContext", e);
		}
	}

	public static SslContext tls12ClientContext(X509Certificate caCertificate) {
		try {
			return GrpcSslContexts.forClient().trustManager(caCertificate).protocols("TLSv1.2").build();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build TLS-1.2 client SslContext", e);
		}
	}

	public static ManagedChannel channel(int port, SslContext sslContext) {
		return NettyChannelBuilder.forAddress("localhost", port).sslContext(sslContext).overrideAuthority("localhost")
				.build();
	}

	public static ManagedChannel plaintextChannel(int port) {
		return NettyChannelBuilder.forAddress("localhost", port).usePlaintext().build();
	}
}
