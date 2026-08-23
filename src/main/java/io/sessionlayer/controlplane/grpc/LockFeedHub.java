package io.sessionlayer.controlplane.grpc;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.grpc.v1.LockEvent;
import io.sessionlayer.controlplane.grpc.v1.LockRemoval;
import io.sessionlayer.controlplane.grpc.v1.LockSnapshot;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.util.concurrent.Queues;

@Component
public class LockFeedHub {

	private static final Logger LOG = LoggerFactory.getLogger(LockFeedHub.class);

	private final AccessLockRepository locks;
	private final Sinks.Many<LockEvent> sink = Sinks.many().multicast().onBackpressureBuffer(Queues.SMALL_BUFFER_SIZE,
			false);

	private final long feedEpoch = System.currentTimeMillis();

	public LockFeedHub(AccessLockRepository locks) {
		this.locks = locks;
	}

	public void publishAdded(AccessLock lock) {
		emit(LockEvent.newBuilder().setAdded(LockCodec.toProto(lock)).build());
	}

	public void publishRemoved(UUID lockId) {
		emit(LockEvent.newBuilder().setRemoved(LockRemoval.newBuilder().setLockId(lockId.toString()).build()).build());
	}

	Flux<LockEvent> liveEvents() {
		return sink.asFlux();
	}

	public int currentSubscribers() {
		return sink.currentSubscriberCount();
	}

	Mono<LockEvent> snapshotEvent() {
		Instant now = Instant.now();
		return locks.findAll().filter(lock -> unexpired(lock, now)).map(LockCodec::toProto).collectList()
				.map(list -> LockEvent.newBuilder()
						.setSnapshot(LockSnapshot.newBuilder().addAllLocks(list).setFeedEpoch(feedEpoch).build())
						.build());
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	// Fan-out is best-effort and must never block or fail the (already committed)
	// CRUD request path. Serialize access (Sinks are single-writer). A non-OK
	// result
	// is diagnostic only: a zero-subscriber drop is covered by the connect-time
	// snapshot, and a genuine terminal failure breaks each per-connection stream
	// (LockFeedService fails the buffer on hub onError/onComplete) so the Gateway
	// reconnects and RESYNCs - this WARN does not by itself trigger a resync.
	private void emit(LockEvent event) {
		Sinks.EmitResult result;
		synchronized (sink) {
			result = sink.tryEmitNext(event);
		}
		if (result.isFailure()) {
			LOG.warn("lock feed hub emit returned {} - delta not fanned out to currently-connected streams", result);
		}
	}
}
