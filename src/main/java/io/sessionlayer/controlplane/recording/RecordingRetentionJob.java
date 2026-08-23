package io.sessionlayer.controlplane.recording;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(value = "sessionlayer.recording.retention.enabled", havingValue = "true", matchIfMissing = true)
public class RecordingRetentionJob {

	private static final Logger LOG = LoggerFactory.getLogger(RecordingRetentionJob.class);

	private final RecordingRetentionService retention;

	public RecordingRetentionJob(RecordingRetentionService retention) {
		this.retention = retention;
	}

	// Fire-and-forget: NEVER block; a retention failure must not abort startup
	// (would crash-loop CP and take auth down).
	@EventListener(ApplicationReadyEvent.class)
	public void pruneOnStartup() {
		retention.prune("startup").subscribe(done -> {
		}, error -> LOG.warn("startup recording retention prune failed (will retry on the schedule)", error));
	}

	@Scheduled(cron = "${sessionlayer.recording.retention.cron:0 0 * * * *}")
	public void pruneScheduled() {
		retention.prune("scheduled").subscribe(done -> {
		}, error -> LOG.warn("scheduled recording retention prune failed (will retry next cycle)", error));
	}
}
