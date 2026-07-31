package io.sessionlayer.controlplane.recording;

import java.util.UUID;

public record RecordingRequestContext(UUID sessionId, UUID nodeId, String principal) {

	public static final RecordingRequestContext EMPTY = new RecordingRequestContext(null, null, null);
}
