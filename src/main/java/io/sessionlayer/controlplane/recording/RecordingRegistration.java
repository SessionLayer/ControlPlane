package io.sessionlayer.controlplane.recording;

import java.util.UUID;

public record RecordingRegistration(UUID recordingId, String objectKey, String wormMode,
		CustomerKeyMaterial customerKey) {
}
