package io.sessionlayer.controlplane.auth;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.FetchSpec;
import reactor.core.publisher.Mono;

class AuthMaintenanceServiceTest {

	// Regression for the startup crash-loop shape: pruneOnStartup()
	// used to .block(Duration.ofSeconds(30)) off ApplicationReadyEvent, so a wedged
	// query (lock contention, a rolling-upgrade instance racing another for the
	// same rows) hung CP boot for 30s and then threw IllegalStateException out of
	// the listener, crash-looping the whole process for an auth-maintenance
	// problem. The listener must return immediately regardless of how long the
	// prune takes.
	@SuppressWarnings("unchecked")
	@Test
	void startupPruneNeverBlocksTheCallingThreadEvenOnAWedgedQuery() {
		DatabaseClient db = mock(DatabaseClient.class);
		DatabaseClient.GenericExecuteSpec spec = mock(DatabaseClient.GenericExecuteSpec.class);
		FetchSpec<Map<String, Object>> fetchSpec = mock(FetchSpec.class);
		when(db.sql(anyString())).thenReturn(spec);
		when(spec.fetch()).thenReturn(fetchSpec);
		when(fetchSpec.rowsUpdated()).thenReturn(Mono.never());

		AuthMaintenanceService service = new AuthMaintenanceService(db);

		assertTimeoutPreemptively(Duration.ofMillis(500), service::pruneOnStartup,
				"startup listener must never block CP boot on a wedged DB call");
	}
}
