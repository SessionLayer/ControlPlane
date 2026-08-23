package io.sessionlayer.controlplane.ca.backend.azure;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AzureKeyVaultProperties.class)
public class AzureKeyVaultConfiguration {
}
