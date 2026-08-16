package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.authz.Cidrs;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

final class BasicEscapeHatchFilter implements WebFilter {

	private final SecurityProperties.BasicAuth config;
	private final PasswordEncoder passwordEncoder;

	BasicEscapeHatchFilter(SecurityProperties.BasicAuth config, PasswordEncoder passwordEncoder) {
		this.config = config;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
			return chain.filter(exchange);
		}
		if (!sourceAllowed(exchange) || config.getUsername() == null || config.getPasswordHash() == null) {
			return chain.filter(exchange);
		}
		String[] creds = decode(header.substring(6));
		if (creds == null) {
			return chain.filter(exchange);
		}
		String user = creds[0];
		String password = creds[1];
		return Mono.fromCallable(() -> {
			boolean userOk = io.sessionlayer.controlplane.auth.Secrets.constantTimeEquals(user, config.getUsername());
			boolean passwordOk = passwordEncoder.matches(password, config.getPasswordHash());
			return userOk && passwordOk;
		}).subscribeOn(Schedulers.boundedElastic()).flatMap(ok -> {
			if (!ok) {
				return chain.filter(exchange);
			}
			RestAuthenticationToken token = new RestAuthenticationToken(
					new AuthenticatedPrincipal(user, List.of(), AuthMethod.BASIC));
			return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(token));
		});
	}

	private boolean sourceAllowed(ServerWebExchange exchange) {
		InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
		// An address the client supplied can never satisfy this gate. Today a
		// forwarded address arrives unresolved, so getAddress() is null and we deny;
		// if that ever changes, the requirement does not. Do NOT "fix" it by falling
		// back to getHostString(), which is the attacker's value.
		if (remote == null || remote.getAddress() == null) {
			return false;
		}
		String ip = remote.getAddress().getHostAddress();
		for (String cidr : config.getAllowedCidrs()) {
			try {
				if (Cidrs.contains(cidr, ip)) {
					return true;
				}
			} catch (RuntimeException malformed) {
				// Deny, never raise: this filter's contract is that it answers for no
				// one. A link-local peer arrives as fe80::1%2 and a mis-typed CIDR has
				// no prefix; both make Cidrs throw, which would surface as a 500.
				// Do NOT "fix" this by stripping the %scope — a scope id is
				// interface-relative and comparing it against a configured CIDR would
				// match a link-local peer against a global rule.
			}
		}
		return false;
	}

	private static String[] decode(String base64) {
		try {
			String decoded = new String(Base64.getDecoder().decode(base64.trim()), StandardCharsets.UTF_8);
			int colon = decoded.indexOf(':');
			if (colon < 0) {
				return null;
			}
			return new String[]{decoded.substring(0, colon), decoded.substring(colon + 1)};
		} catch (IllegalArgumentException badBase64) {
			return null;
		}
	}
}
