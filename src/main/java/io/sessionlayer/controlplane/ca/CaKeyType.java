package io.sessionlayer.controlplane.ca;

public enum CaKeyType {

	ECDSA_NISTP256("ecdsa-p256", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "nistp256",
			"secp256r1", "SHA256withECDSA", 32), ECDSA_NISTP384("ecdsa-p384", "ecdsa-sha2-nistp384",
					"ecdsa-sha2-nistp384-cert-v01@openssh.com", "nistp384", "secp384r1", "SHA384withECDSA",
					48), ECDSA_NISTP521("ecdsa-p521", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
							"nistp521", "secp521r1", "SHA512withECDSA", 66);

	private final String algorithmId;
	private final String keyTypeName;
	private final String certTypeName;
	private final String curveName;
	private final String jcaCurve;
	private final String signatureAlgorithm;
	private final int coordinateBytes;

	CaKeyType(String algorithmId, String keyTypeName, String certTypeName, String curveName, String jcaCurve,
			String signatureAlgorithm, int coordinateBytes) {
		this.algorithmId = algorithmId;
		this.keyTypeName = keyTypeName;
		this.certTypeName = certTypeName;
		this.curveName = curveName;
		this.jcaCurve = jcaCurve;
		this.signatureAlgorithm = signatureAlgorithm;
		this.coordinateBytes = coordinateBytes;
	}

	public String algorithmId() {
		return algorithmId;
	}

	public String keyTypeName() {
		return keyTypeName;
	}

	public String certTypeName() {
		return certTypeName;
	}

	public String curveName() {
		return curveName;
	}

	public String jcaCurve() {
		return jcaCurve;
	}

	public String signatureAlgorithm() {
		return signatureAlgorithm;
	}

	public int coordinateBytes() {
		return coordinateBytes;
	}

	public static CaKeyType fromAlgorithmId(String algorithmId) {
		for (CaKeyType t : values()) {
			if (t.algorithmId.equals(algorithmId)) {
				return t;
			}
		}
		throw new IllegalArgumentException("unsupported/unassemblable CA algorithm: " + algorithmId
				+ " (SessionLayer assembles ECDSA P-256/P-384/P-521; default ecdsa-p256)");
	}

	public static CaKeyType fromKeyTypeName(String keyTypeName) {
		for (CaKeyType t : values()) {
			if (t.keyTypeName.equals(keyTypeName)) {
				return t;
			}
		}
		throw new IllegalArgumentException("unsupported SSH key type: " + keyTypeName);
	}
}
