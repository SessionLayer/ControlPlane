package io.sessionlayer.controlplane.ca.mtls;

import java.security.cert.X509Certificate;

public interface X509CaBackend {

	X509Certificate caCertificate();

	X509Certificate issueLeaf(LeafCertificateSpec spec);
}
