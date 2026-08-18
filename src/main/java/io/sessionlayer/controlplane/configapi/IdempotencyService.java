package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.IdempotencyRecord;
import io.sessionlayer.controlplane.data.runtime.IdempotencyRecordRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * Idempotency-Key replay with scope (principal, method, path, key). Concurrent
 * requests with the same key can both execute; the residual is bounded by
 * resource name-uniqueness (second create conflicts).
 */
@Service
public class IdempotencyService {

	private static final Logger LOG = LoggerFactory.getLogger(IdempotencyService.class);

	private static final String UPSERT = """
			INSERT INTO runtime.idempotency_key
			  (id, principal, method, path, idempotency_key, request_fingerprint, response_status, response_body, expires_at)
			VALUES (:id, :principal, :method, :path, :key, :fingerprint, :status, :body, :expires)
			ON CONFLICT (principal, method, path, idempotency_key) DO UPDATE SET
			  request_fingerprint = EXCLUDED.request_fingerprint,
			  response_status     = EXCLUDED.response_status,
			  response_body       = EXCLUDED.response_body,
			  expires_at          = EXCLUDED.expires_at,
			  created_at          = now()
			""";

	private final IdempotencyRecordRepository records;
	private final DatabaseClient db;
	private final ObjectMapper objectMapper;
	private final IdempotencyProperties properties;

	public IdempotencyService(IdempotencyRecordRepository records, DatabaseClient db, ObjectMapper objectMapper,
			IdempotencyProperties properties) {
		this.records = records;
		this.db = db;
		this.objectMapper = objectMapper;
		this.properties = properties;
	}

	public <T> Mono<ResponseEntity<T>> execute(String key, String principal, String method, String path,
			Object requestBody, Class<T> responseType, Mono<ResponseEntity<T>> action) {
		if (key == null || key.isBlank() || principal == null || principal.isBlank()) {
			return action;
		}
		String fingerprint = fingerprint(method, path, requestBody);
		Instant now = Instant.now();
		return records.findByPrincipalAndMethodAndPathAndIdempotencyKey(principal, method, path, key)
				.filter(existing -> existing.expiresAt().isAfter(now))
				.flatMap(existing -> existing.requestFingerprint().equals(fingerprint)
						? Mono.just(replay(existing, responseType))
						: Mono.<ResponseEntity<T>>error(ApiProblemException.idempotencyConflict()))
				.switchIfEmpty(Mono.defer(
						() -> action.flatMap(response -> store(key, principal, method, path, fingerprint, response, now)
								.onErrorResume(recordFailure -> {
									// The mutation already ran; a failed idempotency record is best-effort
									// (a retry re-executes rather than replays) - never fail the request.
									LOG.warn("idempotency record store failed (best-effort); returning the response",
											recordFailure);
									return Mono.empty();
								}).thenReturn(response))));
	}

	private <T> ResponseEntity<T> replay(IdempotencyRecord existing, Class<T> responseType) {
		HttpStatus status = HttpStatus.valueOf(existing.responseStatus());
		if (existing.responseBody() == null) {
			return ResponseEntity.status(status).build();
		}
		T body = objectMapper.readValue(existing.responseBody(), responseType);
		return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
	}

	private <T> Mono<Void> store(String key, String principal, String method, String path, String fingerprint,
			ResponseEntity<T> response, Instant now) {
		int status = response.getStatusCode().value();
		if (status >= 500) {
			return Mono.empty();
		}
		String body = response.getBody() == null ? null : objectMapper.writeValueAsString(response.getBody());
		var spec = db.sql(UPSERT).bind("id", Uuids.v7()).bind("principal", principal).bind("method", method)
				.bind("path", path).bind("key", key).bind("fingerprint", fingerprint).bind("status", status)
				.bind("expires", now.plus(properties.getTtl()));
		spec = body == null ? spec.bindNull("body", String.class) : spec.bind("body", body);
		return spec.fetch().rowsUpdated().then();
	}

	private String fingerprint(String method, String path, Object requestBody) {
		String canonical = method + "\n" + path + "\n"
				+ (requestBody == null ? "" : objectMapper.writeValueAsString(requestBody));
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (java.security.NoSuchAlgorithmException impossible) {
			throw new IllegalStateException(impossible);
		}
	}
}
