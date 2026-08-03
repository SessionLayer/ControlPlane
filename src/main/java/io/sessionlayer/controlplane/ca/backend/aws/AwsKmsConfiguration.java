package io.sessionlayer.controlplane.ca.backend.aws;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AwsKmsProperties.class)
public class AwsKmsConfiguration {
}
