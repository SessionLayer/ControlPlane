package io.sessionlayer.controlplane.node;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Node lifecycle configuration.
 */
@ConfigurationProperties(prefix = "sessionlayer.node")
public class NodeLifecycleProperties {

	/**
	 * Whether agentless enrollment requires operator approval. When on, a
	 * newly-registered node starts {@code pending} and is excluded from targeting
	 * until activated. Default OFF — a pure-API provisioning flow (autoscaler /
	 * config-mgmt) activates immediately.
	 */
	private boolean enrollmentApprovalRequired = false;

	public boolean isEnrollmentApprovalRequired() {
		return enrollmentApprovalRequired;
	}

	public void setEnrollmentApprovalRequired(boolean enrollmentApprovalRequired) {
		this.enrollmentApprovalRequired = enrollmentApprovalRequired;
	}
}
