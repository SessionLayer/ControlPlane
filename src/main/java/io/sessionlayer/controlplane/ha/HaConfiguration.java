package io.sessionlayer.controlplane.ha;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(HaProperties.class)
public class HaConfiguration {
}
