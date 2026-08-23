package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.grpc.v1.ClientHello;
import io.sessionlayer.controlplane.grpc.v1.ComponentInfo;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.grpc.v1.ServerHello;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class SingleProcessCoLocationIT extends AbstractMtlsIT {

	@Autowired
	private List<BindableService> grpcServices;

	@Test
	void theCpGrpcSurfaceServesInProcessWithPostgresTheOnlyExternalDependency() throws Exception {
		String name = InProcessServerBuilder.generateName();
		InProcessServerBuilder builder = InProcessServerBuilder.forName(name).directExecutor();
		grpcServices.forEach(builder::addService);
		Server server = builder.build().start();
		ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
		try {
			ServerHello reply = HandshakeGrpc.newBlockingStub(channel)
					.negotiate(ClientHello.newBuilder()
							.setClient(ComponentInfo.newBuilder().setName("SessionLayer Gateway").setSemver("0.1.0")
									.setProtocolMin(ProtocolVersions.of(1, 0)).setProtocolMax(ProtocolVersions.of(1, 0))
									.build())
							.build());

			assertThat(reply.getSelected().getMajor()).isEqualTo(1);
			assertThat(reply.getSelected().getMinor()).isEqualTo(0);
			assertThat(reply.getServer().getName()).isEqualTo(ComponentDescriptor.NAME);
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
			server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}
}
