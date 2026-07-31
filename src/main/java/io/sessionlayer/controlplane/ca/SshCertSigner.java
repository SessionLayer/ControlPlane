package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;

public interface SshCertSigner {

	CaKeyType keyType();

	byte[] caPublicKeyBlob();

	String caAuthorizedKey(String comment);

	SignerCapabilities capabilities();

	OpenSshCertificate signCertificate(CertificateRequest request);

	EcdsaSignatures.RS rawSign(byte[] toBeSigned);
}
