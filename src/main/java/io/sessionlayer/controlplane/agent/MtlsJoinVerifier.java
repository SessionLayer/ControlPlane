package io.sessionlayer.controlplane.agent;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Component
public class MtlsJoinVerifier {

	static final byte[] POP_PREFIX = "sessionlayer-mtls-join-pop-v1:".getBytes(StandardCharsets.US_ASCII);

	private final AgentJoinProperties properties;
	private final AtomicReference<Set<TrustAnchor>> anchors = new AtomicReference<>();

	public MtlsJoinVerifier(AgentJoinProperties properties) {
		this.properties = properties;
	}

	public Mono<Void> verify(byte[] operatorCertDer, byte[] popSignature, String nodeName, byte[] csrDer) {
		AgentJoinProperties.Mtls mtls = properties.getMtls();
		if (!mtls.isEnabled() || mtls.getOperatorCaPem() == null || mtls.getOperatorCaPem().isBlank()) {
			return Mono.error(unauthenticated());
		}
		return Mono.<Void>fromCallable(() -> {
			verifyBlocking(operatorCertDer, popSignature, nodeName, csrDer, mtls.getOperatorCaPem());
			return null;
		}).subscribeOn(Schedulers.boundedElastic());
	}

	private void verifyBlocking(byte[] operatorCertDer, byte[] popSignature, String nodeName, byte[] csrDer,
			String operatorCaPem) {
		if (operatorCertDer == null || operatorCertDer.length == 0 || popSignature == null || popSignature.length == 0
				|| csrDer == null || csrDer.length == 0) {
			throw unauthenticated();
		}
		X509Certificate leaf;
		try {
			leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(operatorCertDer));
		} catch (Exception malformed) {
			throw unauthenticated();
		}
		requireChainsToOperatorCa(leaf, operatorCaPem);
		if (!identityMatches(leaf, nodeName)) {
			throw unauthenticated();
		}
		if (!proofOfPossession(leaf, popSignature, csrDer)) {
			throw unauthenticated();
		}
	}

	private void requireChainsToOperatorCa(X509Certificate leaf, String operatorCaPem) {
		try {
			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			var certPath = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
			PKIXParameters params = new PKIXParameters(trustAnchors(operatorCaPem));
			params.setRevocationEnabled(false);
			validator.validate(certPath, params);
		} catch (AgentJoinException e) {
			throw e;
		} catch (Exception invalid) {
			throw unauthenticated();
		}
	}

	private Set<TrustAnchor> trustAnchors(String operatorCaPem) {
		Set<TrustAnchor> cached = anchors.get();
		if (cached != null) {
			return cached;
		}
		Collection<? extends java.security.cert.Certificate> certs;
		try {
			certs = CertificateFactory.getInstance("X.509")
					.generateCertificates(new ByteArrayInputStream(operatorCaPem.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception badPem) {
			throw unauthenticated();
		}
		Set<TrustAnchor> parsed = new HashSet<>();
		for (var cert : certs) {
			if (cert instanceof X509Certificate x509) {
				parsed.add(new TrustAnchor(x509, null));
			}
		}
		if (parsed.isEmpty()) {
			throw unauthenticated();
		}
		anchors.compareAndSet(null, Set.copyOf(parsed));
		return anchors.get();
	}

	private static boolean identityMatches(X509Certificate leaf, String nodeName) {
		if (nodeName == null || nodeName.isBlank()) {
			return false;
		}
		if (nodeName.equals(commonName(leaf))) {
			return true;
		}
		try {
			var sans = leaf.getSubjectAlternativeNames();
			if (sans == null) {
				return false;
			}
			for (List<?> san : sans) {
				if (san.size() >= 2 && san.get(0) instanceof Integer type && (type == 2 || type == 6)
						&& nodeName.equals(san.get(1))) {
					return true;
				}
			}
		} catch (Exception malformed) {
			return false;
		}
		return false;
	}

	private static String commonName(X509Certificate leaf) {
		try {
			X500Name subject = new X500Name(leaf.getSubjectX500Principal().getName());
			RDN[] cns = subject.getRDNs(BCStyle.CN);
			return cns.length == 0 ? null : IETFUtils.valueToString(cns[0].getFirst().getValue());
		} catch (Exception malformed) {
			return null;
		}
	}

	private static boolean proofOfPossession(X509Certificate leaf, byte[] popSignature, byte[] csrDer) {
		try {
			Signature verifier = Signature.getInstance("SHA256withECDSA");
			verifier.initVerify(leaf.getPublicKey());
			verifier.update(POP_PREFIX);
			verifier.update(csrDer);
			return verifier.verify(popSignature);
		} catch (Exception cannotVerify) {
			return false;
		}
	}

	static byte[] popMessage(byte[] csrDer) {
		byte[] message = new byte[POP_PREFIX.length + csrDer.length];
		System.arraycopy(POP_PREFIX, 0, message, 0, POP_PREFIX.length);
		System.arraycopy(csrDer, 0, message, POP_PREFIX.length, csrDer.length);
		return message;
	}

	private static AgentJoinException unauthenticated() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "enrollment refused");
	}
}
