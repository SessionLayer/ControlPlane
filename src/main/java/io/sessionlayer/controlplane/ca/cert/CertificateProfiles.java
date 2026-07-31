package io.sessionlayer.controlplane.ca.cert;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

public final class CertificateProfiles {

	public static final Duration DEFAULT_BACKDATE = Duration.ofMinutes(2);
	public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

	private CertificateProfiles() {
	}

	public static CertificateParameters innerLegSessionCert(String sessionId, String identity, String linuxPrincipal,
			String sourceAddress, Set<String> capabilities, long serial, Instant now) {
		return innerLegSessionCert(sessionId, identity, linuxPrincipal, sourceAddress, capabilities, serial, now,
				DEFAULT_BACKDATE, DEFAULT_TTL);
	}

	public static CertificateParameters innerLegSessionCert(String sessionId, String identity, String linuxPrincipal,
			String sourceAddress, Set<String> capabilities, long serial, Instant now, Duration backdate, Duration ttl) {
		SortedMap<String, String> critical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		if (sourceAddress != null && !sourceAddress.isBlank()) {
			critical.put("source-address", sourceAddress);
		}
		SortedSet<String> extensions = extensionsFor(capabilities);
		String keyId = sessionId + "+" + identity;
		return new CertificateParameters(serial, CertType.USER, keyId, List.of(linuxPrincipal), now.minus(backdate),
				now.plus(ttl), critical, extensions);
	}

	/**
	 * Build the Gateway OUTER host-cert parameters (FR-ADDR-1, Design §9.3/§11):
	 * the short-lived HOST certificate the Gateway presents on the ProxyJump inner
	 * hop so a stock OpenSSH client accepts it as the target node with no TOFU.
	 * {@code key_id = gateway-host:<gatewayName>} for the node-local audit trail.
	 *
	 * <p>
	 * A host cert carries NO {@code permit-*} extensions and no critical options —
	 * it authenticates the Gateway <b>as the host</b>, not a user's capabilities.
	 * The caller (the CP signing service) is responsible for validating the
	 * principals (non-empty; a HOST cert with empty principals is legal on the wire
	 * but useless).
	 */
	public static CertificateParameters gatewayHostCert(String gatewayName, List<String> principals, Instant validAfter,
			Instant validBefore, long serial) {
		return new CertificateParameters(serial, CertType.HOST, "gateway-host:" + gatewayName, List.copyOf(principals),
				validAfter, validBefore, null, null);
	}

	public static SortedSet<String> extensionsFor(Set<String> capabilities) {
		SortedSet<String> extensions = new TreeSet<>(CertificateParameters.BYTE_ORDER);
		if (capabilities.contains("shell")) {
			extensions.add("permit-pty");
		}
		if (capabilities.contains("port_forward_local") || capabilities.contains("port_forward_remote")) {
			extensions.add("permit-port-forwarding");
		}
		// Agent forwarding is ALWAYS refused at the
		// Gateway (FR-SESS-2), so the inner-leg cert MUST NEVER carry
		// permit-agent-forwarding even when RBAC grants agent_forward. Belt-and-
		// suspenders: the node is never told to permit it (two controls, not just
		// the outer-leg refusal).
		if (capabilities.contains("x11")) {
			extensions.add("permit-X11-forwarding");
		}
		return extensions;
	}
}
