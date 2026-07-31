package io.sessionlayer.controlplane.ca.wire;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public final class SshWriter {

	private final ByteArrayOutputStream out = new ByteArrayOutputStream();

	public SshWriter writeByte(int b) {
		out.write(b & 0xFF);
		return this;
	}

	public SshWriter writeBytes(byte[] bytes) {
		out.write(bytes, 0, bytes.length);
		return this;
	}

	public SshWriter writeBoolean(boolean value) {
		return writeByte(value ? 1 : 0);
	}

	public SshWriter writeUint32(long value) {
		if (value < 0 || value > 0xFFFFFFFFL) {
			throw new IllegalArgumentException("uint32 out of range: " + value);
		}
		out.write((int) ((value >>> 24) & 0xFF));
		out.write((int) ((value >>> 16) & 0xFF));
		out.write((int) ((value >>> 8) & 0xFF));
		out.write((int) (value & 0xFF));
		return this;
	}

	public SshWriter writeUint64(long value) {
		writeUint32((value >>> 32) & 0xFFFFFFFFL);
		writeUint32(value & 0xFFFFFFFFL);
		return this;
	}

	public SshWriter writeString(byte[] value) {
		writeUint32(value.length);
		return writeBytes(value);
	}

	public SshWriter writeString(String value) {
		return writeString(value.getBytes(StandardCharsets.UTF_8));
	}

	public SshWriter writeMpint(BigInteger value) {
		if (value.signum() == 0) {
			return writeString(new byte[0]);
		}
		if (value.signum() < 0) {
			throw new IllegalArgumentException("negative mpint not expected for SSH signatures/keys");
		}
		return writeString(value.toByteArray());
	}

	public byte[] toByteArray() {
		return out.toByteArray();
	}
}
