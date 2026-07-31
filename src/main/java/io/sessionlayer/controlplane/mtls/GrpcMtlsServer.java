package io.sessionlayer.controlplane.mtls;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.NettyServerBuilder;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.grpc.AuthInterceptor;
import io.sessionlayer.controlplane.observability.CpTracing;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/**
 * The self-managed CP↔Gateway mTLS gRPC server. Boot's own gRPC server
 * autoconfig is disabled because its builder is created from
 * {@code ServerCredentials}, which freezes the protocol negotiator and forbids
 * installing a custom {@link io.netty.handler.ssl.SslContext}; the server cert
 * is minted at runtime from the internal mTLS CA and requires a TLS-1.3-only
 * context with {@code clientAuth} OPTIONAL. On {@code start()} it loads (or
 * provisions) the internal mTLS CA, mints the server certificate +
 * {@link MtlsServerContext}, binds every {@link BindableService} bean behind
 * the {@link AuthInterceptor}, and starts listening. A failure here crashes the
 * boot (fail closed — the orchestrator heals), never a plaintext fallback.
 */
@Component
public class GrpcMtlsServer implements SmartLifecycle {

	private static final Logger LOG = LoggerFactory.getLogger(GrpcMtlsServer.class);
	private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(60);

	private final MtlsProperties properties;
	private final InternalMtlsCaService mtlsCa;
	private final List<BindableService> services;
	private final CpTracing tracing;

	private volatile Server server;
	private volatile ExecutorService handlerExecutor;
	private volatile int port = -1;
	private volatile boolean running;

	public GrpcMtlsServer(MtlsProperties properties, InternalMtlsCaService mtlsCa, List<BindableService> services,
			CpTracing tracing) {
		this.properties = properties;
		this.mtlsCa = mtlsCa;
		this.services = services;
		this.tracing = tracing;
	}

	@Override
	public synchronized void start() {
		if (running || !properties.getServer().isEnabled()) {
			return;
		}
		try {
			// Blocking on startup thread: the server must not accept traffic until it
			// can present a CA-issued cert.
			X509CaBackend backend = mtlsCa.loadOrProvision("local").block(STARTUP_TIMEOUT);
			if (backend == null) {
				throw new IllegalStateException("internal mTLS CA did not load");
			}
			MtlsProperties.Server serverProps = properties.getServer();
			MtlsServerContext context = MtlsServerContext.create(backend, serverProps.getHostnames(),
					properties.getCertBackdate());
			AuthInterceptor interceptor = new AuthInterceptor(context.trustManager(), tracing);

			this.handlerExecutor = Executors.newFixedThreadPool(serverProps.getHandlerThreads(), runnable -> {
				Thread thread = new Thread(runnable, "mtls-grpc-handler");
				thread.setDaemon(true);
				return thread;
			});

			NettyServerBuilder builder = NettyServerBuilder
					.forAddress(new InetSocketAddress(serverProps.getBindAddress(), serverProps.getPort()))
					.sslContext(context.sslContext()).intercept(interceptor).executor(handlerExecutor)
					.maxInboundMessageSize(serverProps.getMaxInboundMessageSize())
					.maxInboundMetadataSize(serverProps.getMaxInboundMetadataSize())
					.maxConcurrentCallsPerConnection(serverProps.getMaxConcurrentCallsPerConnection())
					.permitKeepAliveTime(serverProps.getPermitKeepAliveTime().toMillis(), TimeUnit.MILLISECONDS)
					.permitKeepAliveWithoutCalls(false)
					.maxConnectionAge(serverProps.getMaxConnectionAge().toMillis(), TimeUnit.MILLISECONDS)
					.maxConnectionAgeGrace(serverProps.getMaxConnectionAgeGrace().toMillis(), TimeUnit.MILLISECONDS)
					.maxConnectionIdle(serverProps.getMaxConnectionIdle().toMillis(), TimeUnit.MILLISECONDS);
			services.forEach(builder::addService);

			this.server = builder.build().start();
			this.port = server.getPort();
			this.running = true;
			LOG.info("mTLS gRPC server listening on {}:{} (TLS 1.3, mutual; internal mTLS CA trust anchor)",
					serverProps.getBindAddress(), port);
		} catch (Exception e) {
			throw new IllegalStateException("failed to start the mTLS gRPC server (fail closed)", e);
		}
	}

	@Override
	public synchronized void stop() {
		// Flip running->false first so readiness reports NOT-READY before drain: the LB
		// stops routing.
		this.running = false;
		Server current = this.server;
		if (current != null) {
			current.shutdown();
			try {
				if (!current.awaitTermination(properties.getServer().getDrainTimeout().toMillis(),
						TimeUnit.MILLISECONDS)) {
					current.shutdownNow();
					current.awaitTermination(2, TimeUnit.SECONDS);
				}
			} catch (InterruptedException e) {
				current.shutdownNow();
				Thread.currentThread().interrupt();
			}
			this.server = null;
		}
		ExecutorService executor = this.handlerExecutor;
		if (executor != null) {
			executor.shutdownNow();
			this.handlerExecutor = null;
		}
	}

	@Override
	public boolean isRunning() {
		return running;
	}

	public int getPort() {
		return port;
	}
}
