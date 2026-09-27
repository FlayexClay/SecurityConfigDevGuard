package com.devguard.worker.analyzer;

import java.nio.file.Path;
import java.util.UUID;

public record ScanContext(
        UUID scanId,
        UUID organizationId,
        UUID projectId,
        UUID repositoryId,
        String cloneUrl,
        String branch,
        /** Directorio de trabajo del scan. Null mientras los analizadores sean simulados. */
        Path workspace) {
}
