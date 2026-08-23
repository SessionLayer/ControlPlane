package io.sessionlayer.controlplane.ca;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.springframework.r2dbc.core.DatabaseClient;
import org.testcontainers.postgresql.PostgreSQLContainer;

final class OwnerDb {

	private OwnerDb() {
	}

	@SuppressWarnings("rawtypes")
	static DatabaseClient of(PostgreSQLContainer postgres) {
		return DatabaseClient.create(ConnectionFactories.get(ConnectionFactoryOptions.builder()
				.option(ConnectionFactoryOptions.DRIVER, "postgresql")
				.option(ConnectionFactoryOptions.HOST, postgres.getHost())
				.option(ConnectionFactoryOptions.PORT, postgres.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT))
				.option(ConnectionFactoryOptions.DATABASE, postgres.getDatabaseName())
				.option(ConnectionFactoryOptions.USER, postgres.getUsername())
				.option(ConnectionFactoryOptions.PASSWORD, postgres.getPassword()).build()));
	}
}
