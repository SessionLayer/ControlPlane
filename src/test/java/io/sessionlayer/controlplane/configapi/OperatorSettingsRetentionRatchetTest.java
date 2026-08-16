package io.sessionlayer.controlplane.configapi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.authz.SessionLimitProperties;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.ApiProblemType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * The retention ratchet moves one way, so a value it accepts it can never take
 * back. That makes the CEILING the ratchet's matching guard rather than a
 * nicety: a retention far enough out overflows the retain-until timestamp when
 * it is stamped onto a recording, every {@code BeginRecording} then fails, and
 * every session is refused (strict) or runs unrecorded (strict off) — with no
 * way back down through this API.
 *
 * <p>
 * The measured boundary is PostgreSQL's: {@code now() + interval '106742278
 * days'} is "timestamp out of range" (year 294276), while Java computes the
 * same {@code Instant} without complaint up to {@code Integer.MAX_VALUE}. So
 * nothing below the API catches this, which is why the ceiling has to.
 *
 * <p>
 * The refusal cases build the service with <b>null</b> audit and transaction
 * collaborators on purpose: a rejection arriving even one step later would
 * dereference them, so "nothing is written" is proven by construction rather
 * than asserted.
 */
class OperatorSettingsRetentionRatchetTest {

	private static final String ACTOR = "operator";
	private static final long VERSION = 3L;
	private static final int STORED_RETENTION = 365;

	@ParameterizedTest
	@ValueSource(ints = {OperatorSettingsConfigService.MAX_RETENTION_DAYS + 1, 106_742_278, Integer.MAX_VALUE})
	void aRecordingRetentionAboveTheCeilingIsRefusedBeforeAnythingIsWritten(int days) {
		ApiProblemException problem = refusal(STORED_RETENTION, days);

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.type().status().value()).isEqualTo(422);
		assertThat(problem.getMessage()).contains("recordingRetentionDays")
				.contains(String.valueOf(OperatorSettingsConfigService.MAX_RETENTION_DAYS));
	}

	@ParameterizedTest
	@ValueSource(ints = {OperatorSettingsConfigService.MAX_RETENTION_DAYS + 1, Integer.MAX_VALUE})
	void anAuditRetentionAboveTheCeilingIsRefusedToo(int days) {
		ApiProblemException problem = refusal(days, STORED_RETENTION);

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.getMessage()).contains("auditRetentionDays");
	}

	/**
	 * The ceiling must not have quietly replaced the ratchet: the destructive
	 * direction stays unreachable at every scope.
	 */
	@Test
	void aDecreaseIsStillRefused() {
		ApiProblemException problem = refusal(STORED_RETENTION - 1, STORED_RETENTION);

		assertThat(problem).isNotNull();
		assertThat(problem.type()).isEqualTo(ApiProblemType.VALIDATION);
		assertThat(problem.getMessage()).contains("may not be decreased");
	}

	/**
	 * The positive control. Without a case that reaches the write, every assertion
	 * above passes against a service that refuses everything — and a guard that
	 * cannot be satisfied looks exactly like a guard that works.
	 */
	@Test
	void theCeilingItselfIsAcceptedAndReachesTheWrite() {
		OperatorSettings saved = accepts(OperatorSettingsConfigService.MAX_RETENTION_DAYS,
				OperatorSettingsConfigService.MAX_RETENTION_DAYS);

		assertThat(saved.auditRetentionDays()).isEqualTo(OperatorSettingsConfigService.MAX_RETENTION_DAYS);
		assertThat(saved.recordingRetentionDays()).isEqualTo(OperatorSettingsConfigService.MAX_RETENTION_DAYS);
		assertThat(saved.origin()).isEqualTo("api");
	}

	@Test
	void anUnchangedRetentionIsAccepted() {
		assertThat(accepts(STORED_RETENTION, STORED_RETENTION).recordingRetentionDays()).isEqualTo(STORED_RETENTION);
	}

	private static ApiProblemException refusal(int auditRetentionDays, int recordingRetentionDays) {
		OperatorSettingsRepository settings = mock(OperatorSettingsRepository.class);
		when(settings.findSingleton()).thenReturn(Mono.just(stored()));

		// null audit + null tx: reaching the persist step would NPE.
		OperatorSettingsConfigService service = new OperatorSettingsConfigService(settings,
				new SessionLimitProperties(), null, null);

		return catchThrowableOfType(ApiProblemException.class, () -> service
				.update(ACTOR, VERSION, auditRetentionDays, recordingRetentionDays, "governance", 120, null, null, null)
				.block());
	}

	private static OperatorSettings accepts(int auditRetentionDays, int recordingRetentionDays) {
		OperatorSettingsRepository settings = mock(OperatorSettingsRepository.class);
		AuditEventStore audit = mock(AuditEventStore.class);
		TransactionalOperator tx = mock(TransactionalOperator.class);
		when(settings.findSingleton()).thenReturn(Mono.just(stored()));
		when(settings.save(any(OperatorSettings.class)))
				.thenAnswer(call -> Mono.just(call.<OperatorSettings>getArgument(0)));
		when(audit.recordChange(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
		when(tx.transactional(ArgumentMatchers.<Mono<OperatorSettings>>any())).thenAnswer(call -> call.getArgument(0));

		OperatorSettings saved = new OperatorSettingsConfigService(settings, new SessionLimitProperties(), audit, tx)
				.update(ACTOR, VERSION, auditRetentionDays, recordingRetentionDays, "governance", 120, null, null, null)
				.block();

		assertThat(saved).isNotNull();
		verify(settings).save(any(OperatorSettings.class));
		return saved;
	}

	private static OperatorSettings stored() {
		return new OperatorSettings(Uuids.v7(), true, null, "local", STORED_RETENTION, "governance", 120, null, null,
				null, null, null, false, null, null, "ecies_p256", null, STORED_RETENTION, true, "default", VERSION,
				null, null);
	}
}
