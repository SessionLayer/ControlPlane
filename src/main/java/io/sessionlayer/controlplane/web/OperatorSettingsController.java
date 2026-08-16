package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.OperatorSettingsApi;
import io.sessionlayer.controlplane.api.model.CaBackend;
import io.sessionlayer.controlplane.api.model.DeploymentManagedField;
import io.sessionlayer.controlplane.api.model.OperatorSettings;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.RecordingCustomerKey;
import io.sessionlayer.controlplane.api.model.RecordingKeySealAlgorithm;
import io.sessionlayer.controlplane.api.model.SetRecordingCustomerKeyRequest;
import io.sessionlayer.controlplane.api.model.UpdateOperatorSettingsRequest;
import io.sessionlayer.controlplane.api.model.WormMode;
import io.sessionlayer.controlplane.configapi.OperatorSettingsConfigService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.recording.CustomerPublicKeys;
import io.sessionlayer.controlplane.recording.SubmittedRecordingKey;
import java.util.Base64;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The recording-key sub-resource is gated on {@code recording:key-manage}
 * rather than {@code settings:write}: its holder can point future recordings at
 * a key whose private half they control, which no other setting confers.
 */
@RestController
public class OperatorSettingsController implements OperatorSettingsApi {

	private final OperatorSettingsConfigService settings;
	private final PlatformAccess access;

	public OperatorSettingsController(OperatorSettingsConfigService settings, PlatformAccess access) {
		this.settings = settings;
		this.access = access;
	}

	@Override
	public Mono<ResponseEntity<OperatorSettings>> getOperatorSettings(ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> access.holds(subject, PlatformPermissions.RECORDING_KEY_MANAGE)
						.flatMap(maySeeKeyRef -> settings.get()
								.map(current -> ResponseEntity.ok(toResource(current, maySeeKeyRef)))));
	}

	@Override
	public Mono<ResponseEntity<OperatorSettings>> updateOperatorSettings(
			Mono<UpdateOperatorSettingsRequest> updateOperatorSettingsRequest, ServerWebExchange exchange) {
		return updateOperatorSettingsRequest.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> settings
						.update(subject.identity(), req.getVersion(), req.getAuditRetentionDays(),
								req.getRecordingRetentionDays(), req.getDefaultWormMode().getValue(),
								req.getOtpTtlSeconds(), req.getDefaultMaxSessionSeconds(),
								req.getDefaultIdleTimeoutSeconds(), req.getDefaultMaxConcurrentSessions())
						// This route is settings:write, which is not the permission that manages
						// the recording key, so its echo of the resource omits keyRef too.
						.map(updated -> ResponseEntity.ok(toResource(updated, false)))));
	}

	@Override
	public Mono<ResponseEntity<RecordingCustomerKey>> getRecordingCustomerKey(ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> access.holds(subject, PlatformPermissions.RECORDING_KEY_MANAGE)
						.flatMap(maySeeKeyRef -> settings.get()
								.map(current -> ResponseEntity.ok(toKeyResource(current, maySeeKeyRef)))));
	}

	@Override
	public Mono<ResponseEntity<RecordingCustomerKey>> setRecordingCustomerKey(
			Mono<SetRecordingCustomerKeyRequest> setRecordingCustomerKeyRequest, ServerWebExchange exchange) {
		return setRecordingCustomerKeyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.RECORDING_KEY_MANAGE,
						subject -> settings.setRecordingKey(subject.identity(), req.getVersion(), req.getPublicKey(),
								req.getSealAlgorithm().getValue(), req.getKeyRef(), req.getExpectedFingerprintSha256(),
								req.getAcknowledgeExistingRecordingsUndecryptable())
								.map(updated -> ResponseEntity.ok(toKeyResource(updated, true)))));
	}

	private OperatorSettings toResource(io.sessionlayer.controlplane.data.config.OperatorSettings current,
			boolean maySeeKeyRef) {
		List<DeploymentManagedField> pinned = settings.deploymentManagedFields().stream()
				.map(DeploymentManagedField::fromValue).toList();
		byte[] key = current.recordingCustomerPublicKey();
		OperatorSettings resource = new OperatorSettings(current.auditRetentionDays(), current.recordingRetentionDays(),
				WormMode.fromValue(current.defaultWormMode()), current.otpTtlSeconds(),
				CaBackend.fromValue(current.defaultCaBackend()), pinned,
				CustomerPublicKeys.isValid(key, current.recordingKeySealAlgorithm()),
				RecordingKeySealAlgorithm.fromValue(current.recordingKeySealAlgorithm()),
				Origin.fromValue(current.origin()), current.version());
		resource.setDefaultMaxSessionSeconds(current.defaultMaxSessionSeconds());
		resource.setDefaultIdleTimeoutSeconds(current.defaultIdleTimeoutSeconds());
		resource.setDefaultMaxConcurrentSessions(current.defaultMaxConcurrentSessions());
		if (maySeeKeyRef) {
			resource.setRecordingKeyRef(current.recordingKeyRef());
		}
		resource.setCreatedAt(ApiConversions.toOffset(current.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(current.updatedAt()));
		return resource;
	}

	// An unprovisioned key is `configured: false`, never a 404: "not provisioned
	// yet" is the normal state of a fresh install, not a missing resource.
	private static RecordingCustomerKey toKeyResource(io.sessionlayer.controlplane.data.config.OperatorSettings current,
			boolean maySeeKeyRef) {
		byte[] der = current.recordingCustomerPublicKey();
		// Usable, not merely present. A deployment whose column was set by hand before
		// this API existed can hold bytes the data plane cannot seal to, and reporting
		// those as configured would tell an operator recording is provisioned while
		// every session fails closed at the first seal.
		boolean configured = CustomerPublicKeys.isValid(der, current.recordingKeySealAlgorithm());
		RecordingCustomerKey resource = new RecordingCustomerKey(configured,
				RecordingKeySealAlgorithm.fromValue(current.recordingKeySealAlgorithm()));
		if (configured) {
			resource.setPublicKey(Base64.getEncoder().encodeToString(der));
			if (maySeeKeyRef) {
				resource.setKeyRef(current.recordingKeyRef());
			}
			resource.setFingerprintSha256(SubmittedRecordingKey.fingerprintSha256(der));
			resource.setUpdatedAt(ApiConversions.toOffset(current.updatedAt()));
		}
		return resource;
	}
}
