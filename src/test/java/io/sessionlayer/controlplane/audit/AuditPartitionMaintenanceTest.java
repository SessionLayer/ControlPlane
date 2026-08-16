package io.sessionlayer.controlplane.audit;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.FetchSpec;
import reactor.core.publisher.Mono;

class AuditPartitionMaintenanceTest {

	// ensureOnStartup() runs off ApplicationReadyEvent, where a throw crash-loops
	// the whole process — so blocking on a wedged partition-create query (two
	// rolling-upgrade instances racing for the same DDL) would take CP boot down
	// for an audit-housekeeping problem. The listener must return immediately
	// regardless of how long ensureAhead() takes.
	@SuppressWarnings("unchecked")
	@Test
	void startupEnsureNeverBlocksTheCallingThreadEvenOnAWedgedQuery() {
		DatabaseClient db = mock(DatabaseClient.class);
		DatabaseClient.GenericExecuteSpec spec = mock(DatabaseClient.GenericExecuteSpec.class);
		FetchSpec<Map<String, Object>> fetchSpec = mock(FetchSpec.class);
		when(db.sql(anyString())).thenReturn(spec);
		when(spec.bind(anyString(), any())).thenReturn(spec);
		when(spec.fetch()).thenReturn(fetchSpec);
		when(fetchSpec.one()).thenReturn(Mono.never());

		AuditPartitionMaintenance maintenance = new AuditPartitionMaintenance(db);

		assertTimeoutPreemptively(Duration.ofMillis(500), maintenance::ensureOnStartup,
				"startup listener must never block CP boot on a wedged DB call");
	}
}
