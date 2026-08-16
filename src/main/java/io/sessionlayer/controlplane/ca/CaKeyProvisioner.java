package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;

public interface CaKeyProvisioner {

	String backend();

	Provisioned provision(Request request);

	record Request(String caKind, String caName, String rotationState, String keyReference, String algorithm) {
	}

	record Provisioned(CaConfig config, CaKeyMaterial material) {
	}
}
