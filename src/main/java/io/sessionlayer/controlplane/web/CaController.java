package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.CasApi;
import io.sessionlayer.controlplane.api.model.CaAlgorithm;
import io.sessionlayer.controlplane.api.model.CaBackend;
import io.sessionlayer.controlplane.api.model.CaKind;
import io.sessionlayer.controlplane.api.model.CaPage;
import io.sessionlayer.controlplane.api.model.CaPublicKey;
import io.sessionlayer.controlplane.api.model.CaResource;
import io.sessionlayer.controlplane.api.model.CaRotationState;
import io.sessionlayer.controlplane.api.model.CreateCaRequest;
import io.sessionlayer.controlplane.api.model.MtlsTrustAnchor;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.RotateCaRequest;
import io.sessionlayer.controlplane.api.model.UpdateCaRequest;
import io.sessionlayer.controlplane.ca.CaPublicKeyService;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.MtlsTrustAnchorService;
import io.sessionlayer.controlplane.configapi.CaConfigService;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
public class CaController implements CasApi {

	private final CaConfigService cas;
	private final MtlsTrustAnchorService trustAnchor;
	private final CaPublicKeyService publicKeys;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public CaController(CaConfigService cas, MtlsTrustAnchorService trustAnchor, CaPublicKeyService publicKeys,
			PlatformAccess access, IdempotencyService idempotency) {
		this.cas = cas;
		this.trustAnchor = trustAnchor;
		this.publicKeys = publicKeys;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<CaPage>> listCas(String cursor, Integer limit, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.list(cursor, limit)
						.map(page -> ResponseEntity.ok(new CaPage(page.items().stream().map(this::toResource).toList())
								.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> createCa(Mono<CreateCaRequest> createCaRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createCaRequest.flatMap(req -> access.withPermission(PlatformPermissions.CA_MANAGE, subject -> {
			Mono<ResponseEntity<CaResource>> action = cas
					.create(subject.identity(), req.getName(), req.getCaKind().getValue(), req.getBackend().getValue(),
							req.getKeyReference(), algorithm(req.getAlgorithm()))
					.map(ca -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(ca)));
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), req, CaResource.class, action);
		}));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> getCa(UUID caId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.get(caId).map(ca -> ResponseEntity.ok(toResource(ca))));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> updateCa(UUID caId, Mono<UpdateCaRequest> updateCaRequest,
			ServerWebExchange exchange) {
		return updateCaRequest.flatMap(req -> access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas
						.update(caId, subject.identity(), req.getVersion(), req.getBackend().getValue(),
								req.getKeyReference(), req.getAlgorithm().getValue())
						.map(ca -> ResponseEntity.ok(toResource(ca)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteCa(UUID caId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.CA_MANAGE,
				subject -> cas.delete(caId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	@Override
	public Mono<ResponseEntity<CaResource>> rotateCa(UUID caId, String idempotencyKey,
			Mono<RotateCaRequest> rotateCaRequest, ServerWebExchange exchange) {
		return rotateCaRequest.defaultIfEmpty(new RotateCaRequest())
				.flatMap(req -> access.withPermission(PlatformPermissions.CA_ROTATE, subject -> {
					// Unlike createCa's algorithm(), a null override here MUST stay null rather
					// than default: rotate inherits the active CA's value, not a fixed one.
					Mono<ResponseEntity<CaResource>> action = cas.rotate(caId, subject.identity(),
							req.getBackend() == null ? null : req.getBackend().getValue(), req.getKeyReference(),
							req.getAlgorithm() == null ? null : req.getAlgorithm().getValue())
							.map(ca -> ResponseEntity.ok(toResource(ca)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, CaResource.class, action);
				}));
	}

	/**
	 * The internal mTLS CA is deliberately absent from the {@code /v1/cas}
	 * collection (which serves the three SSH CA kinds), so this is a read-only
	 * sibling path rather than a member of it. Gated on {@code gateway:enroll}, not
	 * {@code ca:manage}: exporting the public trust anchor is Gateway bring-up, not
	 * CA administration.
	 */
	@Override
	public Mono<ResponseEntity<MtlsTrustAnchor>> getMtlsTrustAnchor(ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.GATEWAY_ENROLL,
				subject -> trustAnchor.activeTrustAnchor()
						.onErrorMap(InternalMtlsCaService.NoMtlsCaAvailable.class,
								absent -> new ApiProblemException(ApiProblemType.NOT_FOUND, absent.getMessage()))
						.map(anchor -> ResponseEntity.ok(new MtlsTrustAnchor(anchor.pem(), anchor.fingerprintSha256(),
								anchor.subject(), ApiConversions.toOffset(anchor.notBefore()),
								ApiConversions.toOffset(anchor.notAfter())))));
	}

	/**
	 * Gated {@code node:enroll}, not {@code ca:manage}: installing a node already
	 * requires that permission and the CA's public key is the material the install
	 * needs. Public verification material only — the projection never touches the
	 * wrapped private key.
	 */
	@Override
	public Mono<ResponseEntity<CaPublicKey>> getCaPublicKey(CaKind caKind, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.NODE_ENROLL,
				subject -> publicKeys.activePublicKey(caKind.getValue())
						.map(key -> ResponseEntity.ok(new CaPublicKey(CaKind.fromValue(key.caKind()),
								CaAlgorithm.fromValue(key.algorithm()), CaRotationState.fromValue(key.rotationState()),
								key.publicKeySpkiDer(), key.opensshPublicKey(), key.fingerprint()))));
	}

	private CaResource toResource(CaConfig ca) {
		CaResource resource = new CaResource(ca.id(), ca.name(), CaKind.fromValue(ca.caKind()),
				CaBackend.fromValue(ca.backend()), ca.keyReference(), CaAlgorithm.fromValue(ca.algorithm()),
				CaRotationState.fromValue(ca.rotationState()), Origin.fromValue(ca.origin()), ca.version());
		resource.setCreatedAt(ApiConversions.toOffset(ca.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(ca.updatedAt()));
		return resource;
	}

	private static String algorithm(CaAlgorithm algorithm) {
		return algorithm == null ? "ecdsa-p256" : algorithm.getValue();
	}
}
