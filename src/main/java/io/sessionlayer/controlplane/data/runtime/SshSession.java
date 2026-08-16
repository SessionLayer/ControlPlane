package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

@Table(schema = "runtime", name = "ssh_session")
public record SshSession(@Id UUID id, String identity, UUID nodeId, String nodeName, String principal, UUID gatewayId,
		String gatewayName, String accessModel, List<String> capabilities, UUID matchedRuleId, String matchedRuleName,
		UUID jitRequestId, UUID breakglassActivationId, Long policyEpoch, Instant grantExpiry, Instant startedAt,
		Instant endedAt, String endReason, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public UUID correlationId() {
		if (jitRequestId != null) {
			return jitRequestId;
		}
		return breakglassActivationId != null ? breakglassActivationId : id;
	}

	public static SshSession create(String identity, UUID nodeId, String nodeName, String principal, UUID gatewayId,
			String gatewayName, String accessModel, List<String> capabilities, UUID matchedRuleId,
			String matchedRuleName, UUID jitRequestId, UUID breakglassActivationId, Long policyEpoch,
			Instant grantExpiry, Instant startedAt) {
		return new SshSession(Uuids.v7(), identity, nodeId, nodeName, principal, gatewayId, gatewayName, accessModel,
				capabilities, matchedRuleId, matchedRuleName, jitRequestId, breakglassActivationId, policyEpoch,
				grantExpiry, startedAt, null, null, null, null, null);
	}

	public SshSession ended(Instant endedAt, String endReason) {
		return new SshSession(id, identity, nodeId, nodeName, principal, gatewayId, gatewayName, accessModel,
				capabilities, matchedRuleId, matchedRuleName, jitRequestId, breakglassActivationId, policyEpoch,
				grantExpiry, startedAt, endedAt, endReason, version, createdAt, updatedAt);
	}

	/**
	 * A mid-session re-Authorize re-decides the SAME session_id — this refreshes
	 * the decision snapshot in place (an UPDATE, since {@code version} and
	 * {@code id} are preserved) rather than colliding with the original INSERT.
	 * {@code startedAt}/{@code endedAt}/{@code endReason} are the connection's own
	 * lifecycle, not the decision's, so they carry over unchanged.
	 */
	public SshSession reauthorized(String identity, UUID nodeId, String nodeName, String principal, UUID gatewayId,
			String gatewayName, String accessModel, List<String> capabilities, UUID matchedRuleId,
			String matchedRuleName, UUID jitRequestId, UUID breakglassActivationId, Long policyEpoch,
			Instant grantExpiry) {
		return new SshSession(id, identity, nodeId, nodeName, principal, gatewayId, gatewayName, accessModel,
				capabilities, matchedRuleId, matchedRuleName, jitRequestId, breakglassActivationId, policyEpoch,
				grantExpiry, startedAt, endedAt, endReason, version, createdAt, updatedAt);
	}
}
