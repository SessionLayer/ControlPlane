package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaKeyStore;
import io.sessionlayer.controlplane.ca.cert.OpenSshCertificateAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;

@Configuration(proxyBeanMethods = false)
public class CaConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(CaConfiguration.class);

	@Bean
	public KekProvider kekProvider(@Value("${sessionlayer.ca.local.kek-base64:}") String kekBase64,
			@Value("${sessionlayer.ca.local.kek-reference:}") String kekReference,
			@Value("${sessionlayer.ca.local.allow-dev-kek:false}") boolean allowDevKek) {
		return new KekProvider(kekBase64, kekReference, allowDevKek);
	}

	@Bean
	public LocalCaKeyStore localCaKeyStore() {
		return new LocalCaKeyStore();
	}

	@Bean
	public OpenSshCertificateAssembler openSshCertificateAssembler() {
		return new OpenSshCertificateAssembler();
	}

	@Bean
	public TransactionalOperator caTransactionalOperator(ReactiveTransactionManager transactionManager) {
		return TransactionalOperator.create(transactionManager);
	}

	@Bean
	@ConditionalOnProperty(value = "sessionlayer.coldstart.enabled", havingValue = "true", matchIfMissing = true)
	public ApplicationRunner caColdStartRunner(CaProvisioningService provisioningService,
			@Value("${sessionlayer.coldstart.timeout-seconds:60}") long timeoutSeconds) {
		return args -> {
			LOG.info("cold start: ensuring operator settings + the three CAs");
			provisioningService.provisionAll().block(java.time.Duration.ofSeconds(timeoutSeconds));
			LOG.info("cold start: CA provisioning complete");
		};
	}
}
