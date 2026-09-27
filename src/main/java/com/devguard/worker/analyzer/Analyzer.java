package com.devguard.worker.analyzer;

import reactor.core.publisher.Flux;

public interface Analyzer {

    String name();
    String version();
    Flux<RawFinding> analyze(ScanContext context);
}
