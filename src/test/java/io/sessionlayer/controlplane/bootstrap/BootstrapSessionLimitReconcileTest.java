package io.sessionlayer.controlplane.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.authz.SessionLimitProperties;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * Two replicas booting together both reconcile the session-limit defaults, so
 * one loses the optimistic-lock race. Propagating that failure out of an
 * {@code ApplicationReadyEvent} listener is the shape that crash-loops a control
 * plane rather than degrading it.
 *
 * <p>
 * These run through {@link BootstrapService#runAtStartup()} rather than the
 * private reconcile, so they exercise the path that actually runs at boot.
 */
class BootstrapSessionLimitReconcileTest {

	private OperatorSettingsRepository settings;
	private SessionLimitProperties sessionLimits;
	private BootstrapService service;

	@BeforeEach
	void setUp() {
		settings = mock(OperatorSettingsRepository.class);
		PlatformRoleRepository roles = mock(PlatformRoleRepository.class);
		RoleBindingRepository bindings = mock(RoleBindingRepository.class);
		when(roles.findAll()).thenReturn(Flux.empty());
		when(bindings.findAll()).thenReturn(Flux.empty());
		// runAtStartup ends with the seeded-role vocabulary check, which is not
		// what these assert; an empty result skips it without stubbing a role.
		when(roles.findByName(org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());

		sessionLimits = new SessionLimitProperties();
		sessionLimits.setDefaultMaxConcurrent(5);

		service = new BootstrapService(settings, roles, bindings, new BootstrapProperties(), sessionLimits,
				mock(AuditEventStore.class), mock(DatabaseClient.class));
	}

	@Test
	void aLostReconcileRaceIsRetriedAndDoesNotFailStartup() {
		when(settings.findSingleton()).thenReturn(Mono.just(completed(null)), Mono.just(completed(5)));
		when(settings.save(any(OperatorSettings.class)))
				.thenReturn(Mono.error(new OptimisticLockingFailureException("sibling replica won")));

		StepVerifier.create(service.runAtStartup()).verifyComplete();

		// The re-read already carries the sibling's value, so re-applying is a
		// no-op and the retry must not write again. A second save here would be
		// the bump-and-retry loop two replicas can sustain indefinitely.
		verify(settings).save(any(OperatorSettings.class));
	}

	@Test
	void theRetryReappliesWhenTheFreshRowStillDiffers() {
		when(settings.findSingleton()).thenReturn(Mono.just(completed(null)), Mono.just(completed(null)));
		when(settings.save(any(OperatorSettings.class))).thenReturn(
				Mono.error(new OptimisticLockingFailureException("sibling replica won")), Mono.just(completed(5)));

		StepVerifier.create(service.runAtStartup()).verifyComplete();

		ArgumentCaptor<OperatorSettings> saved = ArgumentCaptor.forClass(OperatorSettings.class);
		verify(settings, org.mockito.Mockito.times(2)).save(saved.capture());
		assertThat(saved.getAllValues()).allSatisfy(row -> assertThat(row.defaultMaxConcurrentSessions()).isEqualTo(5));
	}

	@Test
	void aRowThatAlreadyMatchesIsNotWrittenAtAll() {
		when(settings.findSingleton()).thenReturn(Mono.just(completed(5)));

		StepVerifier.create(service.runAtStartup()).verifyComplete();

		verify(settings, never()).save(any(OperatorSettings.class));
	}

	private static OperatorSettings completed(Integer maxConcurrent) {
		return new OperatorSettings(Uuids.v7(), true, null, "local", 365, "governance", 120, null, null, maxConcurrent,
				null, null, true, null, null, "ecies_p256", null, 365, true, "default", 1L, null, null);
	}
}
