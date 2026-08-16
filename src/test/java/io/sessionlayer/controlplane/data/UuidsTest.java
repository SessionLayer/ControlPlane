package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UuidsTest {

	@Test
	void generatesVersion7AndVariant2() {
		UUID u = Uuids.v7();
		assertThat(u.version()).isEqualTo(7);
		assertThat(u.variant()).isEqualTo(2);
	}

	@Test
	void isTimeOrderedAcrossMilliseconds() throws InterruptedException {
		UUID first = Uuids.v7();
		Thread.sleep(2);
		UUID second = Uuids.v7();
		assertThat(Long.compareUnsigned(first.getMostSignificantBits(), second.getMostSignificantBits())).isLessThan(0);
	}

	@Test
	void generatesDistinctIds() {
		Set<UUID> seen = new HashSet<>();
		for (int i = 0; i < 10_000; i++) {
			assertThat(seen.add(Uuids.v7())).isTrue();
		}
	}
}
