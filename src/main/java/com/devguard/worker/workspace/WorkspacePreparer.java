package com.devguard.worker.workspace;

import com.devguard.worker.scan.ScanStateRepository.ScanRecord;
import reactor.core.publisher.Mono;

public interface WorkspacePreparer {
    Mono<ScanWorkspace> prepare(ScanRecord record);
    Mono<Void> cleanup(ScanWorkspace workspace);
}
