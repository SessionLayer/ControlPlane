package io.sessionlayer.controlplane.gateway;

import java.util.Collection;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

public final class GatewayNames {

	private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

	private GatewayNames() {
	}

	public static boolean isValid(String name) {
		return name != null && VALID.matcher(name).matches();
	}

	/**
	 * Whether a name may be enrolled as a Gateway: well-formed AND not one of the
	 * Control Plane's own server hostnames. An enrolled identity's name becomes the
	 * CN and dNSName SAN of a serverAuth leaf
	 * ({@code GatewayServerCertificateService}), so a Gateway allowed to call
	 * itself {@code controlplane} would hold a CA-signed certificate that any peer
	 * pinning the internal mTLS CA accepts AS the Control Plane. Fail closed.
	 */
	public static boolean isEnrollable(String name, Collection<String> controlPlaneHostnames) {
		return isValid(name) && !isReserved(name, controlPlaneHostnames);
	}

	private static boolean isReserved(String name, Collection<String> controlPlaneHostnames) {
		if (controlPlaneHostnames == null) {
			return false;
		}
		String candidate = normalize(name);
		return controlPlaneHostnames.stream().filter(Objects::nonNull).map(GatewayNames::normalize)
				.anyMatch(candidate::equals);
	}

	/**
	 * DNS name matching folds case and treats a trailing root dot as the same name,
	 * so a reserved list compared literally would be bypassed by
	 * {@code ControlPlane.} for {@code controlplane}.
	 */
	private static String normalize(String name) {
		String trimmed = name.strip();
		while (trimmed.endsWith(".")) {
			trimmed = trimmed.substring(0, trimmed.length() - 1);
		}
		return trimmed.toLowerCase(Locale.ROOT);
	}
}
