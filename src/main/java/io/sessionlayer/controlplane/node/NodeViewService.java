package io.sessionlayer.controlplane.node;

import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.ha.PresenceFreshness;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Health for an agentless node is always {@code unknown} by design: the CP
 * holds no continuous liveness signal for a node it dials on demand, and runs
 * no probe.
 */
@Service
public class NodeViewService {

	private static final String CONNECTOR_AGENT = "agent";

	private final PresenceRepository presence;
	private final NodeHostKeyRepository hostKeys;
	private final PresenceFreshness freshness;

	public NodeViewService(PresenceRepository presence, NodeHostKeyRepository hostKeys, PresenceFreshness freshness) {
		this.presence = presence;
		this.hostKeys = hostKeys;
		this.freshness = freshness;
	}

	public Mono<NodeView> of(Node node) {
		Instant now = Instant.now();
		Mono<Optional<Presence>> owner = isAgent(node)
				? presence.findById(node.id()).map(Optional::of).defaultIfEmpty(Optional.empty())
				: Mono.just(Optional.empty());
		return Mono.zip(hostKeys.existsByNodeId(node.id()), owner)
				.map(read -> derive(node, read.getT1(), read.getT2().orElse(null), now));
	}

	public Flux<NodeView> ofAll(List<Node> nodes) {
		if (nodes.isEmpty()) {
			return Flux.empty();
		}
		Instant now = Instant.now();
		return Mono.zip(hostKeys.findAnchoredNodeIds().collect(Collectors.toSet()),
				presence.findAll().collectMap(Presence::nodeId)).flatMapMany(read -> {
					Set<UUID> anchored = read.getT1();
					Map<UUID, Presence> owners = read.getT2();
					return Flux.fromIterable(nodes)
							.map(node -> derive(node, anchored.contains(node.id()), owners.get(node.id()), now));
				});
	}

	private NodeView derive(Node node, boolean anchored, Presence owner, Instant now) {
		// Resolved independently of the anchor: owningGateway answers "which Gateway
		// holds this node's agent control channel", which is true or false whether or
		// not anyone ever anchored the node - and routing attaches the same fresh owner
		// with no anchor precondition. `unhealthy` WITH an owner reads "the Agent is
		// connected and you never anchored it", which names the repair.
		String freshOwner = isAgent(node) && freshness.isFresh(owner, now) ? owner.owningGateway() : null;
		if (!anchored) {
			return new NodeView(node, NodeView.HEALTH_UNHEALTHY, freshOwner);
		}
		if (!isAgent(node) || owner == null) {
			return new NodeView(node, NodeView.HEALTH_UNKNOWN, null);
		}
		return freshOwner != null
				? new NodeView(node, NodeView.HEALTH_HEALTHY, freshOwner)
				: new NodeView(node, NodeView.HEALTH_UNREACHABLE, null);
	}

	private static boolean isAgent(Node node) {
		return CONNECTOR_AGENT.equals(node.connectorKind());
	}
}
