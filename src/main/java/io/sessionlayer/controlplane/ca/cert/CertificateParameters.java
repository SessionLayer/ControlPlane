package io.sessionlayer.controlplane.ca.cert;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

public record CertificateParameters(long serial, CertType type, String keyId, List<String> principals,
		Instant validAfter, Instant validBefore, SortedMap<String, String> criticalOptions,
		SortedSet<String> extensions) {

	public static final java.util.Comparator<String> BYTE_ORDER = (a, b) -> {
		byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		int n = Math.min(x.length, y.length);
		for (int i = 0; i < n; i++) {
			int c = (x[i] & 0xFF) - (y[i] & 0xFF);
			if (c != 0) {
				return c;
			}
		}
		return x.length - y.length;
	};

	public CertificateParameters {
		if (validBefore.isBefore(validAfter)) {
			throw new IllegalArgumentException("validBefore must not precede validAfter");
		}
		principals = (principals == null) ? List.of() : List.copyOf(principals);
		if (type == CertType.USER && principals.stream().allMatch(p -> p == null || p.isBlank())) {
			throw new IllegalArgumentException("a USER certificate must have at least one non-blank principal "
					+ "(an empty principals list is valid for every login)");
		}
		criticalOptions = sortedMap(criticalOptions);
		extensions = sortedSet(extensions);
	}

	private static SortedMap<String, String> sortedMap(Map<String, String> in) {
		SortedMap<String, String> m = new TreeMap<>(BYTE_ORDER);
		if (in != null) {
			m.putAll(in);
		}
		return m;
	}

	private static SortedSet<String> sortedSet(java.util.Collection<String> in) {
		SortedSet<String> s = new TreeSet<>(BYTE_ORDER);
		if (in != null) {
			s.addAll(in);
		}
		return s;
	}
}
