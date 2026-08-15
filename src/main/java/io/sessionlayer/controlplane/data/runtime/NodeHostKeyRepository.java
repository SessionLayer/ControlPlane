package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface NodeHostKeyRepository extends ReactiveCrudRepository<NodeHostKey, UUID> {

	Flux<NodeHostKey> findByNodeId(UUID nodeId);

	Mono<Boolean> existsByNodeId(UUID nodeId);

	@Modifying
	@Query("DELETE FROM runtime.node_host_key WHERE node_id = :nodeId")
	Mono<Integer> deleteByNodeId(UUID nodeId);

	/**
	 * Which nodes hold any enrollment anchor at all — the ids only, so listing a
	 * fleet stays one query instead of loading every anchor row for every node.
	 */
	@Query("SELECT DISTINCT node_id FROM runtime.node_host_key")
	Flux<UUID> findAnchoredNodeIds();
}
