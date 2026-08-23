package io.sessionlayer.controlplane.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;

/**
 * The Basic escape hatch is <b>deny-only</b>: every refusal continues the chain
 * <em>unauthenticated</em> rather than answering 401, so the only honest
 * assertion for a refusal is that no {@link RestAuthenticationToken} reached
 * the security context - a status assertion here would pass without proving
 * anything.
 *
 * <p>
 * Non-vacuity is structural: the same capture that must stay empty on every
 * refusal is the one {@link #correctCredentialsFromAnAllowedSourceAuthenticate}
 * requires to be populated, so a broken capture cannot make this file silently
 * green.
 *
 * <p>
 * The end-to-end grant is covered by {@code BasicEscapeHatchBootstrapIT}; this
 * is the refusal matrix.
 */
class BasicEscapeHatchFilterTest {

	private static final String USER = "installer";
	private static final String PASSWORD = "install-time-secret";
	private static final String LOOPBACK = "127.0.0.1/32";

	// Cost 4 (bcrypt's minimum) only to keep the matrix cheap - the property under
	// test is which comparisons run, never the work factor.
	private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder(4);
	private static final String PASSWORD_HASH = ENCODER.encode(PASSWORD);

	private record Outcome(Authentication authentication, int chainInvocations) {
	}

	@Test
	void correctCredentialsFromAnAllowedSourceAuthenticate() {
		Outcome outcome = run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic(USER, PASSWORD));

		assertThat(outcome.authentication()).isInstanceOf(RestAuthenticationToken.class);
		assertThat(outcome.authentication().isAuthenticated()).isTrue();
		assertThat(outcome.authentication().getName()).isEqualTo(USER);
		AuthenticatedPrincipal principal = (AuthenticatedPrincipal) outcome.authentication().getPrincipal();
		assertThat(principal.method()).isEqualTo(AuthMethod.BASIC);
		// The escape hatch conveys no group membership, so it can never satisfy a
		// group-scoped grant on its own - its subject is authorised only by whatever
		// the bootstrap claim bound to that name.
		assertThat(principal.groups()).isEmpty();
		assertThat(outcome.authentication().getAuthorities()).isEmpty();
		assertThat(outcome.chainInvocations()).isEqualTo(1);
	}

	@Test
	void theSchemeIsMatchedCaseInsensitively() {
		Outcome outcome = run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"),
				"basic " + encode(USER + ":" + PASSWORD));

		assertThat(outcome.authentication()).isNotNull();
	}

	@Test
	void anIpv6PeerInsideTheAllowedCidrAuthenticates() {
		Outcome outcome = run(config(USER, PASSWORD_HASH, "::1/128"), peer("::1"), basic(USER, PASSWORD));

		assertThat(outcome.authentication()).isNotNull();
	}

	@Test
	void aSourceOutsideTheAllowedCidrsIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("10.1.2.3"), basic(USER, PASSWORD)));
	}

	@Test
	void aPeerOfADifferentAddressFamilyIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("::1"), basic(USER, PASSWORD)));
	}

	@Test
	void anAbsentRemoteAddressIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), null, basic(USER, PASSWORD)));
	}

	@Test
	void anUnresolvedRemoteAddressIsRefused() {
		InetSocketAddress unresolved = InetSocketAddress.createUnresolved("operator.example", 41234);

		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), unresolved, basic(USER, PASSWORD)));
	}

	@Test
	void anEmptyAllowedCidrListRefusesEveryone() {
		assertRefused(run(config(USER, PASSWORD_HASH), peer("127.0.0.1"), basic(USER, PASSWORD)));
	}

	@Test
	void aWrongPasswordIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic(USER, "wrong")));
	}

	@Test
	void anEmptyPasswordIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic(USER, "")));
	}

	@Test
	void aWrongUsernameIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic("intruder", PASSWORD)));
	}

	@Test
	void anUnsetUsernameRefusesEvenAMatchingPassword() {
		assertRefused(run(config(null, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic(USER, PASSWORD)));
	}

	@Test
	void anUnsetPasswordHashRefusesEveryone() {
		assertRefused(run(config(USER, null, LOOPBACK), peer("127.0.0.1"), basic(USER, PASSWORD)));
	}

	@ParameterizedTest
	@ValueSource(strings = {"Basic !!!!", "Basic ~~~", "Basic aGVsbG8=extra", "Basic ="})
	void malformedBase64IsRefused(String header) {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), header));
	}

	@Test
	void aCredentialWithNoColonIsRefused() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), "Basic " + encode(USER)));
	}

	@ParameterizedTest
	@ValueSource(strings = {"Bearer abc", "Digest username=\"installer\"", "Basic", "Basicabc", " Basic abc"})
	void aHeaderThatIsNotTheBasicSchemeIsIgnored(String header) {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), header));
	}

	@Test
	void noAuthorizationHeaderIsIgnored() {
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), null));
	}

	/** RFC 7617 §2: the user-id ends at the FIRST colon; the rest is password. */
	@Test
	void aPasswordContainingAColonIsKeptWhole() {
		String awkward = "pa:ss:word";
		SecurityProperties.BasicAuth config = config(USER, ENCODER.encode(awkward), LOOPBACK);

		Outcome outcome = run(config, peer("127.0.0.1"), basic(USER, awkward));

		assertThat(outcome.authentication()).isNotNull();
		assertThat(outcome.authentication().getName()).isEqualTo(USER);
	}

	/**
	 * The username comparison is constant-time and, more importantly, does not
	 * short-circuit the password hash: an unknown username costs exactly what a
	 * known one costs, so the hatch cannot be probed for whose name it holds.
	 * Timing is not assertable here; that the hash is still computed is.
	 */
	@Test
	void anUnknownUsernameStillPaysForThePasswordHashSoThereIsNoExistenceOracle() {
		CountingPasswordEncoder unknownUser = new CountingPasswordEncoder();
		CountingPasswordEncoder knownUser = new CountingPasswordEncoder();

		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic("intruder", PASSWORD),
				unknownUser));
		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("127.0.0.1"), basic(USER, "wrong"), knownUser));

		assertThat(unknownUser.matchInvocations()).isEqualTo(knownUser.matchInvocations()).isEqualTo(1);
	}

	@Test
	void aRefusedSourceNeverReachesThePasswordHash() {
		CountingPasswordEncoder encoder = new CountingPasswordEncoder();

		assertRefused(run(config(USER, PASSWORD_HASH, LOOPBACK), peer("10.1.2.3"), basic(USER, PASSWORD), encoder));

		assertThat(encoder.matchInvocations()).isZero();
	}

	/**
	 * A link-local peer's address carries a {@code %scopeId}, which is not a
	 * numeric literal, so the CIDR match must refuse it rather than raise: a raised
	 * exception is a 500, and this filter answers for no one.
	 */
	@Test
	void aScopedIpv6PeerIsRefusedRatherThanRaising() throws Exception {
		InetAddress scoped = Inet6Address.getByAddress(null,
				new byte[]{(byte) 0xfe, (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 2);

		assertRefused(run(config(USER, PASSWORD_HASH, "fe80::/10"), new InetSocketAddress(scoped, 41234),
				basic(USER, PASSWORD)));
	}

	@Test
	void aMalformedAllowedCidrRefusesRatherThanRaising() {
		assertRefused(run(config(USER, PASSWORD_HASH, "127.0.0.1"), peer("127.0.0.1"), basic(USER, PASSWORD)));
	}

	/**
	 * {@code server.forward-headers-strategy=framework} lets
	 * {@link ForwardedHeaderTransformer} rewrite the peer address from a
	 * client-supplied header before any filter runs, so the source gate must never
	 * be satisfiable by a value the client chose.
	 */
	@Test
	void aSpoofedForwardedForInsideTheAllowedCidrsDoesNotAuthenticate() {
		assertRefused(runOn(config(USER, PASSWORD_HASH, LOOPBACK),
				forwarded("X-Forwarded-For", "127.0.0.1", basic(USER, PASSWORD))));
		assertRefused(runOn(config(USER, PASSWORD_HASH, LOOPBACK),
				forwarded("Forwarded", "for=127.0.0.1", basic(USER, PASSWORD))));
	}

	/**
	 * The flip side of the same mechanism, pinned because it is an operational
	 * constraint rather than a bug: the rewritten address is unresolved, so behind
	 * an ingress that adds a forwarded header the hatch cannot be used at all -
	 * even by the genuine peer the CIDRs name. Comparing on the forwarded value
	 * instead would be the bypass above.
	 */
	@Test
	void aForwardedHeaderMakesTheHatchUnusableEvenForAGenuinePeer() {
		assertRefused(runOn(config(USER, PASSWORD_HASH, LOOPBACK),
				forwarded("X-Forwarded-For", "203.0.113.9", basic(USER, PASSWORD))));
	}

	private static void assertRefused(Outcome outcome) {
		assertThat(outcome.authentication()).isNull();
		assertThat(outcome.chainInvocations()).isEqualTo(1);
	}

	private static Outcome run(SecurityProperties.BasicAuth config, InetSocketAddress peer, String authorization) {
		return run(config, peer, authorization, ENCODER);
	}

	private static Outcome run(SecurityProperties.BasicAuth config, InetSocketAddress peer, String authorization,
			PasswordEncoder encoder) {
		return runOn(config, exchange(peer, authorization), encoder);
	}

	private static Outcome runOn(SecurityProperties.BasicAuth config, ServerWebExchange exchange) {
		return runOn(config, exchange, ENCODER);
	}

	private static Outcome runOn(SecurityProperties.BasicAuth config, ServerWebExchange exchange,
			PasswordEncoder encoder) {
		AtomicReference<Authentication> captured = new AtomicReference<>();
		AtomicInteger chainInvocations = new AtomicInteger();
		WebFilterChain chain = downstream -> {
			chainInvocations.incrementAndGet();
			return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
					.doOnNext(captured::set).then();
		};

		new BasicEscapeHatchFilter(config, encoder).filter(exchange, chain).block(Duration.ofSeconds(10));

		return new Outcome(captured.get(), chainInvocations.get());
	}

	private static ServerWebExchange forwarded(String header, String value, String authorization) {
		MockServerHttpRequest request = MockServerHttpRequest.get("/v1/cas")
				.remoteAddress(new InetSocketAddress(InetAddress.ofLiteral("203.0.113.9"), 41234)).header(header, value)
				.header(HttpHeaders.AUTHORIZATION, authorization).build();
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		return exchange.mutate().request(new ForwardedHeaderTransformer().apply(request)).build();
	}

	private static MockServerWebExchange exchange(InetSocketAddress peer, String authorization) {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/v1/cas");
		if (peer != null) {
			request.remoteAddress(peer);
		}
		if (authorization != null) {
			request.header(HttpHeaders.AUTHORIZATION, authorization);
		}
		return MockServerWebExchange.from(request.build());
	}

	private static InetSocketAddress peer(String literal) {
		return new InetSocketAddress(InetAddress.ofLiteral(literal), 41234);
	}

	private static SecurityProperties.BasicAuth config(String username, String passwordHash, String... allowedCidrs) {
		SecurityProperties.BasicAuth config = new SecurityProperties.BasicAuth();
		config.setEnabled(true);
		config.setUsername(username);
		config.setPasswordHash(passwordHash);
		config.setAllowedCidrs(List.of(allowedCidrs));
		return config;
	}

	private static String basic(String user, String password) {
		return "Basic " + encode(user + ":" + password);
	}

	private static String encode(String raw) {
		return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
	}

	private static final class CountingPasswordEncoder implements PasswordEncoder {

		private final AtomicInteger matchInvocations = new AtomicInteger();

		@Override
		public String encode(CharSequence rawPassword) {
			return ENCODER.encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			matchInvocations.incrementAndGet();
			return ENCODER.matches(rawPassword, encodedPassword);
		}

		int matchInvocations() {
			return matchInvocations.get();
		}
	}
}
