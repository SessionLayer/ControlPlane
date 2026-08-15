package io.sessionlayer.controlplane.device;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

class DeviceFlowIT extends AbstractAuthIT {

	@Autowired
	DeviceFlowService deviceFlowService;
	@Autowired
	DeviceFlowRepository deviceFlows;
	@Autowired
	DatabaseClient db;

	@Test
	void lifecycleApprovedFromMatchingSource() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", "conn-1").block();
		assertThat(begun).isNotNull();
		String storedDeviceHash = deviceFlows.findById(begun.deviceFlowId()).block().deviceCodeHash();
		assertThat(storedDeviceHash).isEqualTo(Secrets.sha256Hex(begun.deviceCode()));

		assertThat(deviceFlowService.poll(begun.deviceCode()).block().status()).isEqualTo("pending");

		deviceFlowService.approve(begun.deviceFlowId(), "alice@example.com", "198.51.100.7").block();
		DeviceFlowService.Status status = deviceFlowService.poll(begun.deviceCode()).block();
		assertThat(status.status()).isEqualTo("authorized");
		assertThat(status.identity()).isEqualTo("alice@example.com");
		assertThat(status.sourceContextMatch()).isTrue();
	}

	@Test
	void mismatchedSourceIsFlaggedButStillApprovesByDefault() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		deviceFlowService.approve(begun.deviceFlowId(), "bob@example.com", "203.0.113.200").block();
		DeviceFlowService.Status status = deviceFlowService.poll(begun.deviceCode()).block();
		assertThat(status.status()).isEqualTo("authorized"); // flag-only default (deny-only reducer)
		assertThat(status.sourceContextMatch()).isFalse();
	}

	@Test
	void timeoutExpiresAPendingFlow() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		db.sql("UPDATE runtime.device_flow SET expires_at = now() - interval '1 minute' WHERE id=:id")
				.bind("id", begun.deviceFlowId()).fetch().rowsUpdated().block();
		assertThat(deviceFlowService.poll(begun.deviceCode()).block().status()).isEqualTo("expired");
	}

	@Test
	void unknownDeviceCodePollsEmpty() {
		assertThat(deviceFlowService.poll(Secrets.randomToken(32)).blockOptional()).isEmpty();
	}

	@Test
	void pendingLookupByUserCode() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		assertThat(deviceFlowService.pendingByUserCode(userCodeFor(begun)).blockOptional()).isPresent();
	}

	// The user code is not returned by poll; recover it via the stored hash for the
	// lookup test.
	private String userCodeFor(DeviceFlowService.Begun begun) {
		return begun.userCode();
	}
}
