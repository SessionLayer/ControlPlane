package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import java.security.interfaces.ECPublicKey;

public record CertificateRequest(ECPublicKey subjectPublicKey, CertificateParameters parameters) {
}
