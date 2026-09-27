package com.devguard.worker.event;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ScanLifecycleEvent(
        UUID scanId,
        UUID organizationId,
        UUID projectId,
        String status,
        Integer findingsCount,
        Long durationMs,
        String errorCode,
        String errorMessage,
        OffsetDateTime occurredAt) {

    public static ScanLifecycleEvent started(UUID scanId, UUID orgId, UUID projectId) {
        return new ScanLifecycleEvent(scanId, orgId, projectId, "RUNNING",
                null, null, null, null, OffsetDateTime.now());
    }

    public static ScanLifecycleEvent completed(UUID scanId, UUID orgId, UUID projectId,
                                               int findings, long durationMs) {
        return new ScanLifecycleEvent(scanId, orgId, projectId, "COMPLETED",
                findings, durationMs, null, null, OffsetDateTime.now());
    }

    public static ScanLifecycleEvent failed(UUID scanId, UUID orgId, UUID projectId,
                                            String code, String message) {
        return new ScanLifecycleEvent(scanId, orgId, projectId, "FAILED",
                null, null, code, message, OffsetDateTime.now());
    }

}
