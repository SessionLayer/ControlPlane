package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.api.model.IssueGatewayEnrollmentTokenRequest;
import io.sessionlayer.controlplane.api.model.IssuedGatewayEnrollmentToken;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentTokenService;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformDecision;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class GatewayEnrollmentTokenControllerTest {

	private final GatewayEnrollmentTokenService enrollmentTokens = mock(GatewayEnrollmentTokenService.class);
	private final AuditEventStore audit = mock(AuditEventStore.class);
	private final PlatformAuthorization platformAuthorization = mock(PlatformAuthorization.class);
	private final CurrentAuthentication currentAuthentication = mock(CurrentAuthentication.class);
	private final TransactionalOperator tx = mock(TransactionalOperator.class);
	private final MtlsProperties properties = new MtlsProperties();

	private GatewayEnrollmentTokenController controller;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp() {
		controller = new GatewayEnrollmentTokenController(enrollmentTokens, properties, audit,
				new PlatformAccess(platformAuthorization, currentAuthentication), tx);
		when(currentAuthentication.subject()).thenReturn(Mono.just(new PlatformSubject("admin", List.of())));
		when(audit.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(any(Mono.class))).thenAnswer(invocation -> invocation.getArgument(0));
	}

	@Test
	void issueMintsAuditsAndReturnsTheRawTokenOnce() {
		allowPermission();
		UUID id = UUID.randomUUID();
		when(enrollmentTokens.mint(eq("gw-1"), eq("admin"), any())).thenReturn(Mono
				.just(new GatewayEnrollmentTokenService.MintedEnrollmentToken(id, "RAW-ONCE", "gw-1", Instant.now())));

		StepVerifier
				.create(controller
						.issueGatewayEnrollmentToken(Mono.just(new IssueGatewayEnrollmentTokenRequest("gw-1")), null))
				.assertNext(response -> {
					assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
					IssuedGatewayEnrollmentToken body = response.getBody();
					assertThat(body.getToken()).isEqualTo("RAW-ONCE");
					assertThat(body.getGatewayName()).isEqualTo("gw-1");
					assertThat(body.getSingleUse()).isTrue();
				}).verifyComplete();

		verify(audit).record(eq("admin"), eq(id.toString()), eq("gateway_enrollment_token.issue"), eq("success"),
				isNull(), isNull(), any());
	}

	@Test
	void deniedCallerGetsGenericForbiddenAndMintsNothing() {
		denyPermission();

		StepVerifier
				.create(controller
						.issueGatewayEnrollmentToken(Mono.just(new IssueGatewayEnrollmentTokenRequest("gw-1")), null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();

		verify(enrollmentTokens, never()).mint(any(), any(), any());
	}

	@Test
	void listAndRevokeRequireGatewayEnroll() {
		denyPermission();

		StepVerifier.create(controller.listGatewayEnrollmentTokens(null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();
		StepVerifier.create(controller.revokeGatewayEnrollmentToken(UUID.randomUUID(), null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
				.verifyComplete();

		verify(enrollmentTokens, never()).revoke(any());
	}

	@Test
	void anInvalidGatewayNameFailsClosedBeforeAnyMint() {
		allowPermission();

		StepVerifier
				.create(controller.issueGatewayEnrollmentToken(
						Mono.just(new IssueGatewayEnrollmentTokenRequest("bad name!")), null))
				.verifyErrorSatisfies(
						failure -> assertThat(((ApiProblemException) failure).type().status().value()).isEqualTo(400));

		verify(enrollmentTokens, never()).mint(any(), any(), any());
	}

	@Test
	void anOverlongTtlIsClampedToTheConfiguredMaximum() {
		allowPermission();
		when(enrollmentTokens.mint(any(), any(), any()))
				.thenReturn(Mono.just(new GatewayEnrollmentTokenService.MintedEnrollmentToken(UUID.randomUUID(), "RAW",
						"gw-1", Instant.now())));

		IssueGatewayEnrollmentTokenRequest request = new IssueGatewayEnrollmentTokenRequest("gw-1");
		request.setTtlSeconds((int) Duration.ofDays(1).toSeconds());

		StepVerifier.create(controller.issueGatewayEnrollmentToken(Mono.just(request), null)).expectNextCount(1)
				.verifyComplete();

		ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
		verify(enrollmentTokens).mint(eq("gw-1"), eq("admin"), ttl.capture());
		assertThat(ttl.getValue()).isEqualTo(properties.getEnrollmentTokenMaxTtl());
	}

	@Test
	void anAbsentTtlUsesTheConfiguredDefault() {
		allowPermission();
		when(enrollmentTokens.mint(any(), any(), any()))
				.thenReturn(Mono.just(new GatewayEnrollmentTokenService.MintedEnrollmentToken(UUID.randomUUID(), "RAW",
						"gw-1", Instant.now())));

		StepVerifier
				.create(controller
						.issueGatewayEnrollmentToken(Mono.just(new IssueGatewayEnrollmentTokenRequest("gw-1")), null))
				.expectNextCount(1).verifyComplete();

		ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
		verify(enrollmentTokens).mint(eq("gw-1"), eq("admin"), ttl.capture());
		assertThat(ttl.getValue()).isEqualTo(properties.getEnrollmentTokenTtl());
	}

	@Test
	void revokeIsIdempotentAndAudited() {
		allowPermission();
		UUID id = UUID.randomUUID();
		when(enrollmentTokens.revoke(id)).thenReturn(Mono.empty());

		StepVerifier.create(controller.revokeGatewayEnrollmentToken(id, null))
				.assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
				.verifyComplete();

		verify(audit).record(eq("admin"), eq(id.toString()), eq("gateway_enrollment_token.revoke"), eq("success"),
				isNull(), isNull(), any());
	}

	private void allowPermission() {
		when(platformAuthorization.authorize(any(), eq("gateway:enroll"), isNull())).thenReturn(Mono.just(
				new PlatformDecision(true, PlatformDecision.Reason.ALLOWED, UUID.randomUUID(), "platform-admin")));
	}

	private void denyPermission() {
		when(platformAuthorization.authorize(any(), eq("gateway:enroll"), isNull())).thenReturn(
				Mono.just(new PlatformDecision(false, PlatformDecision.Reason.NO_GRANTING_BINDING, null, null)));
	}
}
