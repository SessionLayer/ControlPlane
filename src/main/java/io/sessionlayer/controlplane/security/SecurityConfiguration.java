package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.machine.MachineTokenProperties;
import io.sessionlayer.controlplane.machine.MachineTokenSigner;
import io.sessionlayer.controlplane.oidc.IdTokenValidator;
import io.sessionlayer.controlplane.oidc.IdpJwtDecoder;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.oidc.ResolvedIdentity;
import io.sessionlayer.controlplane.security.mtls.MtlsAuthenticationConverter;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableConfigurationProperties({SecurityProperties.class, OidcProperties.class, MachineTokenProperties.class,
		io.sessionlayer.controlplane.auth.AuthProperties.class})
public class SecurityConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

	// NOTE: the device namespace is NOT wild-carded. `/v1/auth/device/poll` is
	// public
	// (the opaque device code is its authenticator) but `/v1/auth/device` (begin)
	// is
	// mTLS-gated (Gateway-only) per the contract — a `/v1/auth/device/**` glob
	// would
	// also match the base path and expose begin unauthenticated.
	static final String[] PUBLIC_PATHS = {"/v1/healthz", "/v1/version", "/actuator/health", "/actuator/health/**",
			"/actuator/info", "/v1/auth/verify", "/v1/auth/callback"};

	// Authenticated was never enough here: these carry fleet-wide operational
	// counts, and every machine identity the platform has issued could read them,
	// including a service account with no role binding at all. Both shapes are
	// listed because management.endpoints.web.exposure.include exposes metrics AND
	// prometheus — the same meters by two routes, so gating one alone closes
	// nothing. The health and info endpoints stay public above, so Kubernetes
	// probes are untouched.
	static final String[] METRICS_PATHS = {"/actuator/prometheus", "/actuator/prometheus/**", "/actuator/metrics",
			"/actuator/metrics/**"};

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityWebFilterChain restSecurityFilterChain(ServerHttpSecurity http, MtlsAuthenticationConverter mtlsConverter,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> jwtManagerResolver, SecurityProperties security,
			PasswordEncoder passwordEncoder, MetricsAuthorizationManager metricsAuthorization) {
		http.csrf(ServerHttpSecurity.CsrfSpec::disable).formLogin(ServerHttpSecurity.FormLoginSpec::disable)
				.logout(ServerHttpSecurity.LogoutSpec::disable).httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
				.authorizeExchange(ex -> ex.pathMatchers(PUBLIC_PATHS).permitAll()
						.pathMatchers(HttpMethod.POST, "/v1/oauth2/token", "/v1/auth/backchannel-logout",
								"/v1/bootstrap/claim", "/v1/auth/device/poll")
						.permitAll().pathMatchers(METRICS_PATHS).access(metricsAuthorization).anyExchange()
						.authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(jwtManagerResolver))
				.addFilterAt(mtlsAuthenticationFilter(mtlsConverter), SecurityWebFiltersOrder.AUTHENTICATION);

		SecurityProperties.BasicAuth basic = security.getBasicAuth();
		basic.validateIfEnabled();
		if (basic.isEnabled()) {
			LOG.warn(
					"HTTP Basic escape hatch ENABLED: a discouraged, non-first-class scheme. "
							+ "It is gated to CIDRs {} and MUST sit behind mTLS. Disable it in normal operation.",
					basic.getAllowedCidrs());
			http.addFilterAt(new BasicEscapeHatchFilter(basic, passwordEncoder), SecurityWebFiltersOrder.HTTP_BASIC);
		}
		return http.build();
	}

	private AuthenticationWebFilter mtlsAuthenticationFilter(MtlsAuthenticationConverter converter) {
		AuthenticationWebFilter filter = new AuthenticationWebFilter((ReactiveAuthenticationManager) Mono::just);
		filter.setServerAuthenticationConverter(converter);
		return filter;
	}

	/** Unknown issuer → no manager → fail-closed token rejection. */
	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> jwtManagerResolver(IdpJwtDecoder idpDecoder,
			IdTokenValidator idTokenValidator, OidcProperties oidc, MachineTokenSigner machineTokenSigner,
			MachineTokenProperties machine) {
		ReactiveAuthenticationManager idpManager = idpManager(idpDecoder, idTokenValidator);
		ReactiveAuthenticationManager cpManager = cpMachineTokenManager(machineTokenSigner, machine);
		ReactiveAuthenticationManagerResolver<String> byIssuer = issuer -> {
			if (oidc.isEnabled() && issuer.equals(oidc.getIssuer())) {
				return Mono.just(idpManager);
			}
			if (issuer.equals(machine.getIssuer())) {
				return Mono.just(cpManager);
			}
			return Mono.empty();
		};
		return new JwtIssuerReactiveAuthenticationManagerResolver(byIssuer);
	}

	private ReactiveAuthenticationManager idpManager(IdpJwtDecoder idpDecoder, IdTokenValidator idTokenValidator) {
		JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(idpDecoder);
		manager.setJwtAuthenticationConverter(jwt -> {
			ResolvedIdentity resolved = idTokenValidator.resolve(jwt);
			return Mono.just(new RestAuthenticationToken(
					new AuthenticatedPrincipal(resolved.identity(), resolved.groups(), AuthMethod.OIDC_BEARER)));
		});
		return manager;
	}

	private ReactiveAuthenticationManager cpMachineTokenManager(MachineTokenSigner signer,
			MachineTokenProperties machine) {
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withPublicKey(signer.publicKey()).build();
		// Defense-in-depth: validate iss + aud + token_type, not just exp.
		org.springframework.security.oauth2.core.OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> audience = jwt -> jwt
				.getAudience() != null && jwt.getAudience().contains(machine.getAudience())
						? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
						: org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
								.failure(new org.springframework.security.oauth2.core.OAuth2Error("invalid_token"));
		decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
				new org.springframework.security.oauth2.jwt.JwtTimestampValidator(machine.getClockSkew()),
				new org.springframework.security.oauth2.jwt.JwtIssuerValidator(machine.getIssuer()), audience));
		JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(decoder);
		manager.setJwtAuthenticationConverter(jwt -> {
			if (!"machine".equals(jwt.getClaimAsString("token_type"))) {
				return Mono.error(new org.springframework.security.oauth2.server.resource.InvalidBearerTokenException(
						"not a machine token"));
			}
			List<String> groups = jwt.getClaimAsStringList("groups");
			return Mono.just(new RestAuthenticationToken(new AuthenticatedPrincipal(jwt.getSubject(),
					groups == null ? List.of() : groups, AuthMethod.CLIENT_CREDENTIALS)));
		});
		return manager;
	}
}
