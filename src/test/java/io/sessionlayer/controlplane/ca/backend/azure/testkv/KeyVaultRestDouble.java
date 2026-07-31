package io.sessionlayer.controlplane.ca.backend.azure.testkv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An in-process HTTPS double of the Azure Key Vault key/crypto REST surface,
 * exercised by the genuine {@code CryptographyClient}/{@code KeyClient} rather
 * than by a hand-written double of our own {@code KeyVaultSigner} interface —
 * that is what proves request shape, the bearer-challenge dance, base64url
 * encoding and P1363 handling, none of which a same-process double of our own
 * seam can touch. Backed by a real P-256 key pair so every signature it returns
 * is cryptographically meaningful.
 *
 * <p>
 * Every {@code api-version} query value is accepted and simply recorded. The
 * two REST operations SessionLayer's CA signer needs are implemented:
 *
 * <pre>
 *   GET  /keys/{name}/{version}         -&gt; the JWK + attributes
 *   POST /keys/{name}/{version}/sign    -&gt; {"kid", "value"} (P1363, unless a fault mode says otherwise)
 * </pre>
 */
public final class KeyVaultRestDouble implements AutoCloseable {

	/**
	 * Injectable failures: every one must fail the caller, never fall back.
	 */
	public enum FaultMode {
		NONE, CREDENTIAL_REJECTED, KEY_DISABLED, KEY_NOT_FOUND, RETURN_DER, RETURN_TRUNCATED, RETURN_OVERLONG, RETURN_WRONG_KEY
	}

	/**
	 * One captured request, so tests can assert on wire shape and not only on the
	 * SDK's return value.
	 */
	public record RecordedRequest(String method, String path, String apiVersion, String authorizationHeader,
			String body) {
		public boolean bearerTokenPresent() {
			return authorizationHeader != null && authorizationHeader.startsWith("Bearer ");
		}
	}

	private static final ObjectMapper MAPPER = new ObjectMapper();
	private static final Pattern SIGN_PATH = Pattern.compile("/keys/[^/]+/[^/]+/sign");
	private static final Pattern KEY_PATH = Pattern.compile("/keys/[^/]+/[^/]+");
	private static final String CHALLENGE_TENANT = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000";
	private static final String CHALLENGE_RESOURCE = "https://vault.azure.net";

	private final HttpsServer server;
	private final X509Certificate tlsCertificate;
	private final String keyName;
	private final String keyVersion;
	private final KeyPair vaultKeyPair;
	private final KeyPair otherKeyPair;
	private final List<RecordedRequest> recorded = new CopyOnWriteArrayList<>();
	private volatile FaultMode faultMode = FaultMode.NONE;

	public KeyVaultRestDouble() {
		this(ecKeyPair());
	}

	/**
	 * Bind an explicit key pair (used to reproduce a leading-zero affine
	 * coordinate).
	 */
	public KeyVaultRestDouble(KeyPair vaultKeyPair) {
		this.vaultKeyPair = vaultKeyPair;
		this.otherKeyPair = ecKeyPair();
		this.keyName = "ca-signing-key";
		this.keyVersion = UUID.randomUUID().toString().replace("-", "");
		try {
			TestServerTls.Identity tls = TestServerTls.generate();
			this.tlsCertificate = tls.certificate();
			this.server = HttpsServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
			this.server.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext()) {
				@Override
				public void configure(HttpsParameters params) {
					params.setSSLParameters(getSSLContext().getDefaultSSLParameters());
				}
			});
			this.server.createContext("/", this::handle);
			this.server.setExecutor(Executors.newCachedThreadPool(runnable -> {
				Thread thread = new Thread(runnable, "keyvault-rest-double");
				thread.setDaemon(true);
				return thread;
			}));
			this.server.start();
		} catch (IOException e) {
			throw new IllegalStateException("failed to start the Key Vault REST double", e);
		}
	}

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	public String baseUrl() {
		return "https://127.0.0.1:" + server.getAddress().getPort();
	}

	public String keyName() {
		return keyName;
	}

	public String keyVersion() {
		return keyVersion;
	}

	public String keyIdentifier() {
		return baseUrl() + "/keys/" + keyName + "/" + keyVersion;
	}

	public ECPublicKey publicKey() {
		return (ECPublicKey) vaultKeyPair.getPublic();
	}

	public X509Certificate tlsCertificate() {
		return tlsCertificate;
	}

	public void setFaultMode(FaultMode mode) {
		this.faultMode = mode;
	}

	public List<RecordedRequest> recordedRequests() {
		return List.copyOf(recorded);
	}

	@Override
	public void close() {
		server.stop(0);
	}

	private void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
		try {
			String method = exchange.getRequestMethod();
			String path = exchange.getRequestURI().getPath();
			String apiVersion = queryParam(exchange.getRequestURI().getRawQuery(), "api-version");
			String authorization = exchange.getRequestHeaders().getFirst("Authorization");
			String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			recorded.add(new RecordedRequest(method, path, apiVersion, authorization, body));

			boolean bearerPresent = authorization != null && authorization.startsWith("Bearer ");
			if (!bearerPresent || faultMode == FaultMode.CREDENTIAL_REJECTED) {
				respondChallenge(exchange);
				return;
			}

			Matcher sign = SIGN_PATH.matcher(path);
			Matcher key = KEY_PATH.matcher(path);
			if (sign.matches()) {
				handleSign(exchange, body);
			} else if (key.matches()) {
				handleGetKey(exchange);
			} else {
				respondJson(exchange, 404, errorBody("NotFound", "no route for " + path));
			}
		} finally {
			exchange.close();
		}
	}

	private void respondChallenge(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
		exchange.getResponseHeaders().add("WWW-Authenticate",
				"Bearer authorization=\"" + CHALLENGE_TENANT + "\", resource=\"" + CHALLENGE_RESOURCE + "\"");
		respondJson(exchange, 401, errorBody("Unauthorized", "authentication required"));
	}

	private void handleGetKey(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
		if (faultMode == FaultMode.KEY_NOT_FOUND) {
			respondJson(exchange, 404, errorBody("KeyNotFound", "a key with (name/version) was not found"));
			return;
		}
		if (faultMode == FaultMode.KEY_DISABLED) {
			respondJson(exchange, 403, errorBody("Forbidden", "operation is not allowed on a disabled key"));
			return;
		}
		ECPublicKey pub = publicKey();
		ObjectNode root = MAPPER.createObjectNode();
		ObjectNode key = root.putObject("key");
		key.put("kid", keyIdentifier());
		key.put("kty", "EC");
		key.put("crv", "P-256");
		key.put("x", base64Url(fixedWidth(pub.getW().getAffineX(), 32)));
		key.put("y", base64Url(fixedWidth(pub.getW().getAffineY(), 32)));
		ArrayNode ops = key.putArray("key_ops");
		ops.add("sign");
		ops.add("verify");
		root.putObject("attributes").put("enabled", true);
		respondJson(exchange, 200, root);
	}

	private void handleSign(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
		if (faultMode == FaultMode.KEY_NOT_FOUND) {
			respondJson(exchange, 404, errorBody("KeyNotFound", "a key with (name/version) was not found"));
			return;
		}
		if (faultMode == FaultMode.KEY_DISABLED) {
			respondJson(exchange, 403, errorBody("Forbidden", "operation is not allowed on a disabled key"));
			return;
		}
		JsonNode request = MAPPER.readTree(body);
		String alg = request.path("alg").asText(null);
		String value = request.path("value").asText(null);
		if (!"ES256".equals(alg)) {
			respondJson(exchange, 400, errorBody("BadParameter", "algorithm '" + alg + "' is not valid for this key"));
			return;
		}
		byte[] digest = Base64.getUrlDecoder().decode(value);
		byte[] signature = signFor(digest);
		ObjectNode root = MAPPER.createObjectNode();
		root.put("kid", keyIdentifier());
		root.put("value", base64Url(signature));
		respondJson(exchange, 200, root);
	}

	private byte[] signFor(byte[] digest) {
		try {
			KeyPair signingKey = faultMode == FaultMode.RETURN_WRONG_KEY ? otherKeyPair : vaultKeyPair;
			Signature ecdsa = Signature.getInstance("NONEwithECDSA");
			ecdsa.initSign(signingKey.getPrivate());
			ecdsa.update(digest);
			byte[] der = ecdsa.sign();
			return switch (faultMode) {
				case RETURN_DER -> der;
				case RETURN_TRUNCATED -> Arrays.copyOf(p1363(der), 63);
				case RETURN_OVERLONG -> Arrays.copyOf(p1363(der), 65);
				default -> p1363(der);
			};
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Key Vault REST double failed to sign", e);
		}
	}

	/**
	 * The direction {@link EcdsaSignatures} does not need in production: DER (what
	 * the JDK signs) -&gt; P1363 (what a real vault's {@code ES256} returns).
	 */
	private static byte[] p1363(byte[] der) {
		EcdsaSignatures.RS rs = EcdsaSignatures.fromDer(der);
		byte[] out = new byte[64];
		System.arraycopy(fixedWidth(rs.r(), 32), 0, out, 0, 32);
		System.arraycopy(fixedWidth(rs.s(), 32), 0, out, 32, 32);
		return out;
	}

	private static byte[] fixedWidth(BigInteger value, int length) {
		byte[] raw = value.toByteArray();
		byte[] out = new byte[length];
		int start = raw.length > length ? raw.length - length : 0;
		int len = raw.length - start;
		System.arraycopy(raw, start, out, length - len, len);
		return out;
	}

	private static void respondJson(com.sun.net.httpserver.HttpExchange exchange, int status, JsonNode body)
			throws IOException {
		byte[] bytes = MAPPER.writeValueAsBytes(body);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		try (var responseBody = exchange.getResponseBody()) {
			responseBody.write(bytes);
		}
	}

	private static ObjectNode errorBody(String code, String message) {
		ObjectNode root = MAPPER.createObjectNode();
		ObjectNode error = root.putObject("error");
		error.put("code", code);
		error.put("message", message);
		return root;
	}

	private static String base64Url(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}

	private static String queryParam(String rawQuery, String name) {
		if (rawQuery == null) {
			return null;
		}
		for (String pair : rawQuery.split("&")) {
			int eq = pair.indexOf('=');
			String key = eq < 0 ? pair : pair.substring(0, eq);
			if (key.equals(name)) {
				return eq < 0 ? "" : pair.substring(eq + 1);
			}
		}
		return null;
	}
}
