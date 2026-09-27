package com.devguard.worker.risk;

import java.util.UUID;

public record FindingSnapshot(
        UUID id,
        String category,
        String severity,
        String status,
        String filePath,
        String fixedVersion,
        Double cvssScore,
        long ageDays,
        /** Accion que resuelve el hallazgo; varios la comparten. */
        String remediationKey) {
}
