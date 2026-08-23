package io.sessionlayer.controlplane.ca.cert;

public enum CertType {

	USER(1), HOST(2);

	private final int value;

	CertType(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}
}
