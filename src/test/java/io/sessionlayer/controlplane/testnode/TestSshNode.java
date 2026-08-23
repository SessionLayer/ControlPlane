package io.sessionlayer.controlplane.testnode;

import java.nio.file.Path;
import java.util.Base64;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.Transferable;

public final class TestSshNode {

	private static final String IMAGE_NAME = "sessionlayer-testnode:it";
	private static final Path CONTEXT = Path.of("src/test/resources/testnode/sshd");

	private TestSshNode() {
	}

	@SuppressWarnings("resource")
	public static GenericContainer<?> start(String trustedUserCaAuthorizedKey) {
		GenericContainer<?> node = new GenericContainer<>(
				new ImageFromDockerfile(IMAGE_NAME, false).withFileFromPath(".", CONTEXT))
				.withEnv("TRUSTED_USER_CA", trustedUserCaAuthorizedKey).withExposedPorts(22)
				.waitingFor(Wait.forListeningPort());
		node.start();
		return node;
	}

	public static byte[] generateInnerKey(GenericContainer<?> node, String path) throws Exception {
		exec(node, "ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", path);
		Container.ExecResult pub = node.execInContainer("cat", path + ".pub");
		String[] parts = pub.getStdout().trim().split("\\s+");
		return Base64.getDecoder().decode(parts[1]);
	}

	public static void installCertificate(GenericContainer<?> node, String path, String certificateLine)
			throws Exception {
		node.copyFileToContainer(Transferable.of(certificateLine + "\n"), path);
	}

	public static String handshake(GenericContainer<?> node, String keyPath, String certPath, String user)
			throws Exception {
		Container.ExecResult result = node.execInContainer("ssh", "-i", keyPath, "-o", "CertificateFile=" + certPath,
				"-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
				"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", user + "@localhost", "echo HANDSHAKE_OK");
		return result.getStdout() + result.getStderr();
	}

	public static String inspectCertificate(GenericContainer<?> node, String certPath) throws Exception {
		return node.execInContainer("ssh-keygen", "-L", "-f", certPath).getStdout();
	}

	private static void exec(GenericContainer<?> node, String... command) throws Exception {
		Container.ExecResult result = node.execInContainer(command);
		if (result.getExitCode() != 0) {
			throw new IllegalStateException("command failed (" + result.getExitCode() + "): "
					+ String.join(" ", command) + "\n" + result.getStdout() + result.getStderr());
		}
	}
}
