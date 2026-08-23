package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;

final class ReactiveBridge {

	private ReactiveBridge() {
	}

	static <T> void forward(Mono<T> result, StreamObserver<T> observer, Duration timeout, String operation) {
		AtomicReference<Disposable> subscription = new AtomicReference<>();
		if (observer instanceof ServerCallStreamObserver<T> serverObserver) {
			serverObserver.setOnCancelHandler(() -> {
				Disposable current = subscription.get();
				if (current != null) {
					current.dispose();
				}
			});
		}
		subscription.set(result.timeout(timeout).subscribe(value -> {
			observer.onNext(value);
			observer.onCompleted();
		}, error -> observer.onError(GrpcErrors.toStatus(error, operation))));
	}
}
