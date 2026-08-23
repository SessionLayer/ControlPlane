package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Component
public class DecisionContextSigner {

	private static final SecureRandom RANDOM = new SecureRandom();

	private final InternalMtlsCaService mtlsCa;
	private final MtlsProperties mtlsProperties;
	private final AuthzProperties authzProperties;
	private final AtomicReference<Material> material = new AtomicReference<>();

	public DecisionContextSigner(InternalMtlsCaService mtlsCa, MtlsProperties mtlsProperties,
			AuthzProperties authzProperties) {
		this.mtlsCa = mtlsCa;
		this.mtlsProperties = mtlsProperties;
		this.authzProperties = authzProperties;
	}

	private record Material(PrivateKey privateKey, X509Certificate leaf, X509Certificate caCertificate,
			Instant notAfter) {
	}

	public Mono<SignedDecisionContext> sign(DecisionContext context) {
		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(context);
		byte[] canonical = DecisionContextCodec.canonicalBytes(proto);
		return resolveMaterial()
				.flatMap(m -> Mono
						.fromCallable(() -> new SignedDecisionContext(proto, canonical, ecdsaSign(m, canonical),
								der(m.leaf()), List.of(der(m.caCertificate()))))
						.subscribeOn(Schedulers.boundedElastic()));
	}

	private Mono<Material> resolveMaterial() {
		return Mono.defer(() -> {
			Material cached = material.get();
			if (cached != null && !nearExpiry(cached)) {
				return Mono.just(cached);
			}
			return mtlsCa.activeBackend()
					.flatMap(backend -> Mono.fromCallable(() -> mint(backend)).subscribeOn(Schedulers.boundedElastic()))
					.doOnNext(material::set);
		});
	}

	private boolean nearExpiry(Material current) {
		Instant refreshAt = current.notAfter().minus(authzProperties.getContextSignerCertTtl().dividedBy(3));
		return !Instant.now().isBefore(refreshAt);
	}

	private Material mint(X509CaBackend backend) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
			KeyPair keyPair = generator.generateKeyPair();
			Instant now = Instant.now();
			Instant notAfter = now.plus(authzProperties.getContextSignerCertTtl());
			LeafCertificateSpec spec = new LeafCertificateSpec(keyPair.getPublic(), "decision-context-signer",
					List.of(), List.of(DecisionContextSigning.SIGNER_URI), LeafPurpose.CONTEXT_SIGNER, serial(),
					now.minus(mtlsProperties.getCertBackdate()), notAfter);
			X509Certificate leaf = backend.issueLeaf(spec);
			return new Material(keyPair.getPrivate(), leaf, backend.caCertificate(), notAfter);
		} catch (Exception e) {
			throw new IllegalStateException("failed to mint the decision-context signer", e);
		}
	}

	private static byte[] ecdsaSign(Material m, byte[] canonicalBytes) {
		try {
			Signature signature = Signature.getInstance(DecisionContextSigning.SIGNATURE_ALGORITHM);
			signature.initSign(m.privateKey());
			signature.update(DecisionContextSigning.DOMAIN_PREFIX);
			signature.update(canonicalBytes);
			return signature.sign();
		} catch (Exception e) {
			throw new IllegalStateException("failed to sign the decision context", e);
		}
	}

	private static byte[] der(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException("failed to encode a certificate", e);
		}
	}

	private static BigInteger serial() {
		BigInteger serial = new BigInteger(159, RANDOM);
		return serial.signum() == 0 ? BigInteger.ONE : serial;
	}
}
