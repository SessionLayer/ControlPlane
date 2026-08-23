package io.sessionlayer.controlplane.bootstrap;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sessionlayer.bootstrap")
public class BootstrapProperties {

	private String adminSubject;

	private String adminSubjectKind = "user";

	public String getAdminSubject() {
		return adminSubject;
	}

	public void setAdminSubject(String adminSubject) {
		this.adminSubject = adminSubject;
	}

	public String getAdminSubjectKind() {
		return adminSubjectKind;
	}

	public void setAdminSubjectKind(String adminSubjectKind) {
		this.adminSubjectKind = adminSubjectKind;
	}
}
