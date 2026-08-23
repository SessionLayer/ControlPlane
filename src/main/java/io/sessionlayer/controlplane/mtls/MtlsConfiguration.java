package io.sessionlayer.controlplane.mtls;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MtlsProperties.class)
public class MtlsConfiguration {
}
