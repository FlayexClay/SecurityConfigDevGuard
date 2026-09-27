package com.devguard.worker.workspace;

import java.nio.file.Path;

public record ScanWorkspace(Path path, String commitSha, long sizeBytes) {
    public static ScanWorkspace none() { return new ScanWorkspace(null, null, 0); }
    public boolean isEmpty() { return path == null; }
}
