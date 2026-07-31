package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.ServerCallStreamObserver;
import org.reactivestreams.Subscription;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Flux;

final class ServerStreamBridge<T> extends BaseSubscriber<T> {

	private final ServerCallStreamObserver<T> observer;
	private final String operation;

	private ServerStreamBridge(ServerCallStreamObserver<T> observer, String operation) {
		this.observer = observer;
		this.operation = operation;
	}

	static <T> void forward(Flux<T> source, ServerCallStreamObserver<T> observer, String operation) {
		ServerStreamBridge<T> bridge = new ServerStreamBridge<>(observer, operation);
		observer.setOnCancelHandler(bridge::dispose);
		observer.setOnReadyHandler(bridge::onReady);
		source.subscribe(bridge);
	}

	@Override
	protected void hookOnSubscribe(Subscription subscription) {
		request(1);
	}

	@Override
	protected void hookOnNext(T value) {
		observer.onNext(value);
		if (observer.isReady()) {
			request(1);
		}
		// else: the transport is saturated — onReady() resumes demand.
	}

	@Override
	protected void hookOnComplete() {
		observer.onCompleted();
	}

	@Override
	protected void hookOnError(Throwable error) {
		observer.onError(GrpcErrors.toStatus(error, operation));
	}

	private void onReady() {
		if (!isDisposed() && observer.isReady()) {
			request(1);
		}
	}
}
