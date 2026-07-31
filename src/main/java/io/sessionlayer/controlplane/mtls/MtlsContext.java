package io.sessionlayer.controlplane.mtls;

import io.grpc.Context;

public final class MtlsContext {

	public static final Context.Key<MtlsPeer> PEER = Context.key("sessionlayer.mtls.peer");

	private MtlsContext() {
	}

	public static MtlsPeer peer() {
		MtlsPeer peer = PEER.get();
		return peer == null ? MtlsPeer.NONE : peer;
	}
}
