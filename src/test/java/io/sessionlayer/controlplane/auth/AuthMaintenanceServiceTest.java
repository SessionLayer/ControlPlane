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

	// pruneOnStartup() runs off ApplicationReadyEvent, where a throw crash-loops
	// the whole process — so blocking on a wedged query (lock contention, a
	// rolling-upgrade instance racing another for the same rows) would take CP boot
	// down for an auth-maintenance problem. The listener must return immediately
	// regardless of how long the prune takes.
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
