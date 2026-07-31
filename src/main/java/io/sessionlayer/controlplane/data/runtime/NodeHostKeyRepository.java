package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface NodeHostKeyRepository extends ReactiveCrudRepository<NodeHostKey, UUID> {

	Flux<NodeHostKey> findByNodeId(UUID nodeId);
}
