package io.sessionlayer.controlplane.ca.cert;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

class CertificateProfilesTest {

	@Test
	void grantedAgentForwardNeverYieldsPermitAgentForwarding() {
		assertThat(CertificateProfiles.extensionsFor(Set.of("shell", "agent_forward", "x11")))
				.contains("permit-pty", "permit-X11-forwarding").doesNotContain("permit-agent-forwarding");
	}

	@Test
	void defaultDenyGrantsNoExtensionForShellExecSftp() {
		// shell → permit-pty is the only flag extension; exec/sftp/scp are enforced at
		// the Gateway channel layer, not via a cert extension.
		assertThat(CertificateProfiles.extensionsFor(Set.of("exec", "sftp", "scp"))).isEmpty();
		assertThat(CertificateProfiles.extensionsFor(Set.of("shell"))).containsExactly("permit-pty");
	}
}
