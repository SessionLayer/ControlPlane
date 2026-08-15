package io.sessionlayer.controlplane.mtls;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.mtls")
public class MtlsProperties {

	private final Server server = new Server();

	private Duration identityCertTtl = Duration.ofHours(24);

	private Duration enrollmentTokenTtl = Duration.ofMinutes(10);

	private Duration enrollmentTokenMaxTtl = Duration.ofHours(1);

	private Duration sessionSigningTokenTtl = Duration.ofSeconds(120);

	private Duration hostCertTtl = Duration.ofHours(1);

	private Duration certBackdate = Duration.ofMinutes(2);

	/**
	 * Server-side deadline applied to every mTLS RPC handler: a hung DB / saturated
	 * R2DBC pool surfaces as {@code DEADLINE_EXCEEDED} rather than a hung call.
	 */
	private Duration rpcTimeout = Duration.ofSeconds(15);

	public Server getServer() {
		return server;
	}

	public Duration getRpcTimeout() {
		return rpcTimeout;
	}

	public void setRpcTimeout(Duration rpcTimeout) {
		this.rpcTimeout = rpcTimeout;
	}

	public Duration getIdentityCertTtl() {
		return identityCertTtl;
	}

	public void setIdentityCertTtl(Duration identityCertTtl) {
		this.identityCertTtl = identityCertTtl;
	}

	public Duration getEnrollmentTokenTtl() {
		return enrollmentTokenTtl;
	}

	public void setEnrollmentTokenTtl(Duration enrollmentTokenTtl) {
		this.enrollmentTokenTtl = enrollmentTokenTtl;
	}

	public Duration getEnrollmentTokenMaxTtl() {
		return enrollmentTokenMaxTtl;
	}

	public void setEnrollmentTokenMaxTtl(Duration enrollmentTokenMaxTtl) {
		this.enrollmentTokenMaxTtl = enrollmentTokenMaxTtl;
	}

	public Duration getSessionSigningTokenTtl() {
		return sessionSigningTokenTtl;
	}

	public void setSessionSigningTokenTtl(Duration sessionSigningTokenTtl) {
		this.sessionSigningTokenTtl = sessionSigningTokenTtl;
	}

	public Duration getHostCertTtl() {
		return hostCertTtl;
	}

	public void setHostCertTtl(Duration hostCertTtl) {
		this.hostCertTtl = hostCertTtl;
	}

	public Duration getCertBackdate() {
		return certBackdate;
	}

	public void setCertBackdate(Duration certBackdate) {
		this.certBackdate = certBackdate;
	}

	public static class Server {
		private boolean enabled = true;
		private int port = 9090;
		private String bindAddress = "0.0.0.0";
		private List<String> hostnames = new ArrayList<>(List.of("localhost", "controlplane"));

		private int maxInboundMessageSize = 64 * 1024;
		private int maxInboundMetadataSize = 16 * 1024;
		private int maxConcurrentCallsPerConnection = 128;

		private int handlerThreads = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);
		private Duration permitKeepAliveTime = Duration.ofSeconds(30);
		private Duration maxConnectionAge = Duration.ofMinutes(30);
		private Duration maxConnectionAgeGrace = Duration.ofSeconds(30);
		private Duration maxConnectionIdle = Duration.ofMinutes(5);
		private Duration drainTimeout = Duration.ofSeconds(10);

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public int getPort() {
			return port;
		}

		public void setPort(int port) {
			this.port = port;
		}

		public String getBindAddress() {
			return bindAddress;
		}

		public void setBindAddress(String bindAddress) {
			this.bindAddress = bindAddress;
		}

		public List<String> getHostnames() {
			return hostnames;
		}

		public void setHostnames(List<String> hostnames) {
			this.hostnames = hostnames;
		}

		public int getMaxInboundMessageSize() {
			return maxInboundMessageSize;
		}

		public void setMaxInboundMessageSize(int maxInboundMessageSize) {
			this.maxInboundMessageSize = maxInboundMessageSize;
		}

		public int getMaxInboundMetadataSize() {
			return maxInboundMetadataSize;
		}

		public void setMaxInboundMetadataSize(int maxInboundMetadataSize) {
			this.maxInboundMetadataSize = maxInboundMetadataSize;
		}

		public int getMaxConcurrentCallsPerConnection() {
			return maxConcurrentCallsPerConnection;
		}

		public void setMaxConcurrentCallsPerConnection(int maxConcurrentCallsPerConnection) {
			this.maxConcurrentCallsPerConnection = maxConcurrentCallsPerConnection;
		}

		public int getHandlerThreads() {
			return handlerThreads;
		}

		public void setHandlerThreads(int handlerThreads) {
			this.handlerThreads = handlerThreads;
		}

		public Duration getPermitKeepAliveTime() {
			return permitKeepAliveTime;
		}

		public void setPermitKeepAliveTime(Duration permitKeepAliveTime) {
			this.permitKeepAliveTime = permitKeepAliveTime;
		}

		public Duration getMaxConnectionAge() {
			return maxConnectionAge;
		}

		public void setMaxConnectionAge(Duration maxConnectionAge) {
			this.maxConnectionAge = maxConnectionAge;
		}

		public Duration getMaxConnectionAgeGrace() {
			return maxConnectionAgeGrace;
		}

		public void setMaxConnectionAgeGrace(Duration maxConnectionAgeGrace) {
			this.maxConnectionAgeGrace = maxConnectionAgeGrace;
		}

		public Duration getMaxConnectionIdle() {
			return maxConnectionIdle;
		}

		public void setMaxConnectionIdle(Duration maxConnectionIdle) {
			this.maxConnectionIdle = maxConnectionIdle;
		}

		public Duration getDrainTimeout() {
			return drainTimeout;
		}

		public void setDrainTimeout(Duration drainTimeout) {
			this.drainTimeout = drainTimeout;
		}
	}
}
