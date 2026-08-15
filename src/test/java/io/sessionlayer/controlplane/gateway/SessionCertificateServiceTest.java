package io.sessionlayer.controlplane.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.backend.CaSigningFailedException;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.SessionSigningToken;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * {@code SessionCertificateService.sign} must audit every fail-closed path it
 * takes, each with its own distinguishable reason: a client fault, an absent
 * CA, and a CA that was reached and refused. The three must never collapse into
 * one, since an operator reads the reason to decide where to look.
 */
class SessionCertificateServiceTest {

	private static final UUID GATEWAY_ID = UUID.randomUUID();
	private static final String FINGERPRINT = "fp-current";

	private final SessionSigningTokenService tokenService = mock(SessionSigningTokenService.class);
	private final CaSignerService caSigner = mock(CaSignerService.class);
	private final GatewayIdentityRepository gatewayIdentities = mock(GatewayIdentityRepository.class);
	private final AuditEventStore audit = mock(AuditEventStore.class);

	private SessionCertificateService service;
	private byte[] subjectKeyBlob;

	/**
	 * A stand-in {@link CaSigningFailedException}, not
	 * {@code AzureKeyVaultSigner.KeyVaultSigningException}: this proves
	 * {@code SessionCertificateService} honors the shared contract for any backend
	 * that reaches it, not one wired specifically to Key Vault.
	 */
	private static final class StubCaSigningFailure extends CaSigningFailedException {
		StubCaSigningFailure(String message, Throwable cause) {
			super(message, cause);
		}
	}

	@BeforeEach
	void setUp() throws Exception {
		service = new SessionCertificateService(tokenService, caSigner, gatewayIdentities, audit);
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(gatewayIdentities.findById(GATEWAY_ID)).thenReturn(Mono.just(GatewayIdentity.create("gw-1", "mtls-ref",
				FINGERPRINT, 0, "token", "active", Instant.now(), Instant.now().plusSeconds(3600))));
		when(tokenService.consume(eq("raw-token"), eq(GATEWAY_ID), any()))
				.thenReturn(Mono.just(SessionSigningToken.create("hash", GATEWAY_ID, UUID.randomUUID(),
						UUID.randomUUID(), "alice", List.of("shell"), null, Instant.now().plusSeconds(60))));

		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		subjectKeyBlob = SshEcdsaPublicKeys.encode((ECPublicKey) generator.generateKeyPair().getPublic(),
				CaKeyType.ECDSA_NISTP256);
	}

	@Test
	@SuppressWarnings("unchecked")
	void aBackendThatRefusedToSignWritesADeniedAuditEventCarryingNoVaultContent() {
		String vaultResponse = "SECRET-VAULT-RESPONSE-BODY-403";
		when(caSigner.activeSigner("session")).thenReturn(
				Mono.error(new StubCaSigningFailure("CA refused to sign", new IllegalStateException(vaultResponse))));

		StepVerifier
				.create(service.sign(GATEWAY_ID, FINGERPRINT, "raw-token", subjectKeyBlob, SignRequestContext.EMPTY))
				.verifyError(StubCaSigningFailure.class);

		ArgumentCaptor<Map<String, String>> detail = ArgumentCaptor.forClass(Map.class);
		verify(audit).record(eq(GATEWAY_ID.toString()), isNull(), eq("session.sign"), eq("denied"), isNull(), isNull(),
				detail.capture());
		assertThat(detail.getValue()).containsEntry("reason", "ca_signing_failed");
		// The reason is a fixed constant, never derived from the exception's message
		// -- this is the guard that matters, since the cause (kept for the server
		// log) is where the key service's own response text legitimately lives.
		assertThat(detail.getValue().toString()).doesNotContain(vaultResponse);
	}

	@Test
	void anAbsentCaIsAuditedWithItsOwnDistinctReason() {
		when(caSigner.activeSigner("session"))
				.thenReturn(Mono.error(new CaSignerService.NoSignerAvailable("no active session CA")));

		StepVerifier
				.create(service.sign(GATEWAY_ID, FINGERPRINT, "raw-token", subjectKeyBlob, SignRequestContext.EMPTY))
				.verifyError(CaSignerService.NoSignerAvailable.class);

		verify(audit).record(eq(GATEWAY_ID.toString()), isNull(), eq("session.sign"), eq("denied"), isNull(), isNull(),
				eq(Map.of("reason", "ca_unavailable")));
	}

	@Test
	void aClientFaultIsAuditedWithItsOwnDistinctReason() {
		// A fingerprint that does not pin to the identity's current or previous
		// value takes the same GatewayRequestException path a malformed/expired
		// token would, without needing a second mock for those.
		StepVerifier.create(service.sign(GATEWAY_ID, "stale-or-stolen-fingerprint", "raw-token", subjectKeyBlob,
				SignRequestContext.EMPTY)).verifyError(GatewayRequestException.class);

		verify(audit).record(eq(GATEWAY_ID.toString()), isNull(), eq("session.sign"), eq("denied"), isNull(), isNull(),
				eq(Map.of("reason", "PERMISSION_DENIED")));
	}
}
