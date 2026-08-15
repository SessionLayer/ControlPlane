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
 * Derives a node's {@code health} and {@code owningGateway} at read time. Both
 * were once columns nothing ever wrote, so the API reported every working node
 * as {@code unknown} with no owner — an operator following the install guide
 * read a successful Agent install as a failure. The truth lives in
 * {@code runtime.presence} (which Gateway holds the agent control channel, and
 * how recently) and {@code runtime.node_host_key} (whether the node has any
 * enrollment-anchored host identity at all).
 *
 * <p>
 * Health, in precedence order:
 * <ol>
 * <li>{@code unhealthy} — no host anchor. The node is enrolled but unusable:
 * the Gateway never TOFUs, so every session to it aborts.</li>
 * <li>agent-connected — {@code healthy} on a fresh presence claim,
 * {@code unreachable} on a stale one, {@code unknown} when no Gateway has ever
 * claimed it (the Agent has not joined yet).</li>
 * <li>agentless — {@code unknown}, always. The CP holds no continuous liveness
 * signal for a node it dials on demand, and runs no probe.</li>
 * </ol>
 *
 * <p>
 * {@code owningGateway} is the presence owner's name and only while that claim
 * is fresh, by the same {@link PresenceFreshness} rule the authorizer routes on
 * — so the API can never name an owner routing has already given up on.
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

	/**
	 * The same derivation for a whole listing in two queries — one anchor probe and
	 * one presence read for the page, never a pair per node.
	 */
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
		// The owner is resolved FIRST and independently of the anchor, because the two
		// fields answer different questions: owningGateway is "which Gateway holds
		// this node's agent control channel", which is true or false regardless of
		// whether anyone ever anchored the node, and health is the field that says the
		// node is unusable. Suppressing the owner on the anchorless branch conflated
		// them — and disagreed with routing, which attaches the same fresh owner with
		// no anchor precondition. It also threw away the most useful thing an operator
		// can be told about a node an Agent join created: `unhealthy` WITH an owner
		// reads "the Agent is connected and you never anchored it", which names the
		// repair.
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
