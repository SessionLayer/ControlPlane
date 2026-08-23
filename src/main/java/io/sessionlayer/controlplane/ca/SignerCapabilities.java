package io.sessionlayer.controlplane.ca;

import java.util.Set;

public record SignerCapabilities(Set<String> algorithms) {

	public SignerCapabilities {
		algorithms = Set.copyOf(algorithms);
	}

	public boolean supports(String algorithmId) {
		return algorithms.contains(algorithmId);
	}

	public static SignerCapabilities of(CaKeyType... types) {
		return new SignerCapabilities(java.util.Arrays.stream(types).map(CaKeyType::algorithmId)
				.collect(java.util.stream.Collectors.toUnmodifiableSet()));
	}
}
