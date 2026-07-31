package io.sessionlayer.controlplane.security.mtls;

import io.sessionlayer.controlplane.security.AuthMethod;
import io.sessionlayer.controlplane.security.AuthenticatedPrincipal;
import io.sessionlayer.controlplane.security.RestAuthenticationToken;
import java.security.cert.X509Certificate;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Independent re-validation against internal CA; fail-closed (no weaker
 * fallback).
 */
@Component
public class MtlsAuthenticationConverter implements ServerAuthenticationConverter {

	private static final Logger LOG = LoggerFactory.getLogger(MtlsAuthenticationConverter.class);

	private final InternalCaTrustManagerProvider trustManagers;

	public MtlsAuthenticationConverter(InternalCaTrustManagerProvider trustManagers) {
		this.trustManagers = trustManagers;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		SslInfo ssl = exchange.getRequest().getSslInfo();
		if (ssl == null || ssl.getPeerCertificates() == null || ssl.getPeerCertificates().length == 0) {
			return Mono.empty();
		}
		X509Certificate[] chain = ssl.getPeerCertificates();
		return trustManagers.trustManager().flatMap(tm -> Mono.fromCallable(() -> {
			try {
				tm.checkClientTrusted(chain, chain[0].getPublicKey().getAlgorithm());
			} catch (Exception invalid) {
				LOG.debug("REST mTLS client certificate rejected on re-validation: {}", invalid.toString());
				return (Authentication) null;
			}
			String identity = MtlsIdentities.identityOf(chain[0]);
			if (identity == null) {
				LOG.debug("REST mTLS client certificate has no usable identity (URI SAN / CN)");
				return (Authentication) null;
			}
			return new RestAuthenticationToken(new AuthenticatedPrincipal(identity, List.of(), AuthMethod.MTLS));
		}).subscribeOn(Schedulers.boundedElastic())).flatMap(Mono::justOrEmpty);
	}
}
