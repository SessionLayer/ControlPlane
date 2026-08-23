package io.sessionlayer.controlplane.auth;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.auth")
public class AuthProperties {

	private int otpEntropyBytes = 16;

	private final RateLimit otpVerify = new RateLimit(5, Duration.ofMinutes(1));
	private final RateLimit tokenEndpoint = new RateLimit(30, Duration.ofMinutes(1));
	private final RateLimit devicePoll = new RateLimit(60, Duration.ofMinutes(1));

	public int getOtpEntropyBytes() {
		return otpEntropyBytes;
	}

	public void setOtpEntropyBytes(int otpEntropyBytes) {
		this.otpEntropyBytes = otpEntropyBytes;
	}

	public RateLimit getOtpVerify() {
		return otpVerify;
	}

	public RateLimit getTokenEndpoint() {
		return tokenEndpoint;
	}

	public RateLimit getDevicePoll() {
		return devicePoll;
	}

	public static class RateLimit {
		private int max;
		private Duration window;

		public RateLimit() {
		}

		RateLimit(int max, Duration window) {
			this.max = max;
			this.window = window;
		}

		public int getMax() {
			return max;
		}

		public void setMax(int max) {
			this.max = max;
		}

		public Duration getWindow() {
			return window;
		}

		public void setWindow(Duration window) {
			this.window = window;
		}
	}
}
