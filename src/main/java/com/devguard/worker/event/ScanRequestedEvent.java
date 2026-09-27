package com.devguard.worker.event;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ScanRequestedEvent(
        UUID scanId,
        UUID organizationId,
        UUID projectId,
        UUID repositoryId,
        String triggerType,
        String branch,
        OffsetDateTime requestedAt) {
}
