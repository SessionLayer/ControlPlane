package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.test.context.TestPropertySource;

/**
 * WORM readiness opt-in: adding worm to readiness group makes down store
 * deregister CP.
 */
@TestPropertySource(properties = "management.endpoint.health.group.readiness.include=readinessState,worm")
class WormReadinessIncludeIT extends AbstractDataIT {

	@Autowired
	private HealthEndpointGroups groups;

	@Test
	void wormJoinsReadinessWhenIncluded() {
		assertThat(groups.get("readiness")).isNotNull();
		assertThat(groups.get("readiness").isMember("worm")).isTrue();
	}
}
