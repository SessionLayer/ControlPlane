package io.sessionlayer.controlplane.recording;

import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "sessionlayer.recording.worm")
public class WormProperties {

	@NotBlank
	private String endpoint = "http://localhost:9000";

	@NotBlank
	private String region = "us-east-1";

	@NotBlank
	private String bucket = "sessionlayer-recordings";

	private String accessKey = "sessionlayer";

	private String secretKey = "sessionlayer-dev-secret";

	private boolean pathStyleAccess = true;

	private Duration credentialTtl = Duration.ofSeconds(120);

	public String getEndpoint() {
		return endpoint;
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}

	public String getRegion() {
		return region;
	}

	public void setRegion(String region) {
		this.region = region;
	}

	public String getBucket() {
		return bucket;
	}

	public void setBucket(String bucket) {
		this.bucket = bucket;
	}

	public String getAccessKey() {
		return accessKey;
	}

	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public boolean isPathStyleAccess() {
		return pathStyleAccess;
	}

	public void setPathStyleAccess(boolean pathStyleAccess) {
		this.pathStyleAccess = pathStyleAccess;
	}

	public Duration getCredentialTtl() {
		return credentialTtl;
	}

	public void setCredentialTtl(Duration credentialTtl) {
		this.credentialTtl = credentialTtl;
	}
}
