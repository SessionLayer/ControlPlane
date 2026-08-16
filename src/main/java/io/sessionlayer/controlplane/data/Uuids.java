package io.sessionlayer.controlplane.data;

import java.security.SecureRandom;
import java.util.UUID;

public final class Uuids {

	private static final SecureRandom RANDOM = new SecureRandom();

	private Uuids() {
	}

	public static UUID v7() {
		long unixTsMs = System.currentTimeMillis();
		byte[] rand = new byte[10];
		RANDOM.nextBytes(rand);

		long rand12 = (((long) (rand[0] & 0xFF) << 8) | (rand[1] & 0xFF)) & 0x0FFFL;
		long msb = ((unixTsMs & 0xFFFFFFFFFFFFL) << 16)
				| 0x7000L
				| rand12;

		long lsb = 0L;
		for (int i = 2; i < 10; i++) {
			lsb = (lsb << 8) | (rand[i] & 0xFFL);
		}
		lsb &= 0x3FFFFFFFFFFFFFFFL;
		lsb |= 0x8000000000000000L; // variant 0b10

		return new UUID(msb, lsb);
	}
}
