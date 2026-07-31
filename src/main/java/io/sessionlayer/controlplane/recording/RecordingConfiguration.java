package io.sessionlayer.controlplane.recording;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({WormProperties.class, RecordingAccessProperties.class})
public class RecordingConfiguration {
}
