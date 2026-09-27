package com.devguard.worker.workspace;

import com.devguard.worker.scan.ScanStateRepository.ScanRecord;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@ConditionalOnProperty(name = "devguard.worker.simulated", havingValue = "true",
        matchIfMissing = true)
public class NoopWorkspacePreparer implements WorkspacePreparer {

    @Override
    public Mono<ScanWorkspace> prepare (ScanRecord record) {
        return Mono.just(ScanWorkspace.none());
    }

    @Override
    public Mono<Void> cleanup(ScanWorkspace workspace) {
        return Mono.empty();
    }
}
