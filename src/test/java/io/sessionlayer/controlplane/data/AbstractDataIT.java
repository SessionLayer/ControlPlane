package io.sessionlayer.controlplane.data;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest(properties = "spring.grpc.server.port=0")
abstract class AbstractDataIT {

	@SuppressWarnings("resource") // shared singleton; stopped by Ryuk at JVM exit, not per-class
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	static {
		POSTGRES.start();
	}

	static DatabaseClient ownerClient() {
		return DatabaseClient.create(ConnectionFactories.get(ConnectionFactoryOptions.builder()
				.option(ConnectionFactoryOptions.DRIVER, "postgresql")
				.option(ConnectionFactoryOptions.HOST, POSTGRES.getHost())
				.option(ConnectionFactoryOptions.PORT, POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT))
				.option(ConnectionFactoryOptions.DATABASE, POSTGRES.getDatabaseName())
				.option(ConnectionFactoryOptions.USER, POSTGRES.getUsername())
				.option(ConnectionFactoryOptions.PASSWORD, POSTGRES.getPassword()).build()));
	}

	static final String RUNTIME_ROLE = "cp_runtime";
	static final String RUNTIME_PASSWORD = "cp_runtime";

	@DynamicPropertySource
	static void dataSources(DynamicPropertyRegistry registry) {
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> RUNTIME_ROLE);
		registry.add("spring.r2dbc.password", () -> RUNTIME_PASSWORD);
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> RUNTIME_PASSWORD);
		registry.add("sessionlayer.coldstart.enabled", () -> "false");
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
		registry.add("sessionlayer.audit.partition-maintenance.enabled", () -> "false");
		registry.add("sessionlayer.bootstrap.enabled", () -> "false");
		registry.add("sessionlayer.auth.maintenance.enabled", () -> "false");
		registry.add("sessionlayer.mtls.server.enabled", () -> "false");
	}
}
