package com.devguard.worker.scan;

import com.devguard.worker.analyzer.Analyzer;
import com.devguard.worker.analyzer.ScanContext;
import com.devguard.worker.event.DevGuardTopics;
import com.devguard.worker.event.EventPublisher;
import com.devguard.worker.event.ScanLifecycleEvent;
import com.devguard.worker.event.ScanRequestedEvent;
import com.devguard.worker.finding.FindingWriter;
import com.devguard.worker.risk.ScoreService;
import com.devguard.worker.workspace.ScanWorkspace;
import com.devguard.worker.workspace.WorkspacePreparer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class ScanProcessor {

    private static final Logger log = LoggerFactory.getLogger(ScanProcessor.class);

    private static final Duration ANALYZER_TIMEOUT = Duration.ofMinutes(10);

    private final ScanStateRepository scans;
    private final FindingWriter findings;
    private final EventPublisher events;
    private final List<Analyzer> analyzers;
    private final WorkspacePreparer workspaces;
    private final ScoreService scoreService;


    public ScanProcessor(ScanStateRepository scans, FindingWriter findings,
                         EventPublisher events, List<Analyzer> analyzers,
                         WorkspacePreparer workspaces, ScoreService scoreService) {
        this.scans = scans;
        this.findings = findings;
        this.events = events;
        this.analyzers = analyzers;
        this.workspaces = workspaces;
        this.scoreService = scoreService;
    }

    public Mono<Void> process(ScanRequestedEvent event) {
        // Reclamar primero. Si no se consigue, el mensaje es un duplicado o
        // pertenece a un scan que ya termino: se descarta sin ruido.
        return scans.claim(event.scanId())
                .flatMap(claimed -> {
                    if (!claimed) {
                        log.info("Scan {} ya reclamado o en estado terminal: se descarta",
                                event.scanId());
                        return Mono.empty();
                    }
                    return runScan(event);
                })
                .then();
    }

    private Mono<Void> runScan(ScanRequestedEvent event) {
        long startedAt = System.currentTimeMillis();

        return scans.load(event.scanId())
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "El scan no existe en la base: " + event.scanId())))
                // Comprobar la autorizacion aqui tambien, no solo en la API.
                // Entre la peticion y el procesado pudo revocarse, y el worker
                // es quien va a tocar el repositorio de verdad.
                .flatMap(record -> record.repositoryAuthorized()
                        ? Mono.just(record)
                        : Mono.error(new SecurityException(
                        "El repositorio perdio la autorizacion antes del analisis")))
                .flatMap(record -> events.publish(DevGuardTopics.SCAN_STARTED,
                                record.organizationId().toString(),
                                ScanLifecycleEvent.started(record.scanId(),
                                        record.organizationId(), record.projectId()))
                        .thenReturn(record))
                // usingWhen garantiza la limpieza del workspace: se ejecuta
                // al completar, al fallar Y al cancelarse. Un try/finally
                // normal no cubre la cancelacion, y un clonado de cientos de
                // megabytes que no se borra llena el disco de la instancia y
                // afecta a todos los tenants, no solo al que pidio el scan.
                .flatMap(record -> Mono.usingWhen(
                        workspaces.prepare(record),
                        workspace -> analyze(record, workspace, startedAt),
                        workspaces::cleanup,
                        (workspace, error) -> workspaces.cleanup(workspace),
                        workspaces::cleanup))
                .onErrorResume(error -> handleFailure(event, error));
    }

    private Mono<Void> analyze(ScanStateRepository.ScanRecord record,
                               ScanWorkspace workspace, long startedAt) {
        ScanContext context = new ScanContext(
                record.scanId(), record.organizationId(), record.projectId(),
                record.repositoryId(), record.cloneUrl(), record.branch(),
                workspace.path());

        AtomicInteger total = new AtomicInteger();
        AtomicInteger nuevos = new AtomicInteger();

        return Flux.fromIterable(analyzers)
                // Secuencial a proposito. Los analizadores reales
                // compiten por memoria y CPU; correrlos en
                // paralelo en una instancia de 4 GiB es la via
                // rapida al OOM killer.
                .concatMap(analyzer -> runAnalyzer(analyzer, context, total, nuevos))
                .collectList()
                .flatMap(resultados -> decide(record, workspace, resultados, total.get(),
                        nuevos.get(), System.currentTimeMillis() - startedAt));
    }



    /**
     * El desenlace de un scan depende de cuantos analizadores lograron correr.
     *
     * Un scan en el que fallaron TODOS no puede terminar como COMPLETED. En un
     * producto de seguridad eso seria lo peor posible: "completado, 0
     * hallazgos" es indistinguible de un proyecto perfectamente seguro. Seria
     * un falso resultado limpio, que es mas peligroso que no tener resultado.
     *
     *   todos bien        -> COMPLETED
     *   algunos fallaron  -> COMPLETED con error_code PARTIAL_ANALYSIS
     *   todos fallaron    -> FAILED
     */
    private Mono<Void> decide(ScanStateRepository.ScanRecord record, ScanWorkspace workspace,
                              List<Boolean> resultados, int total, int nuevos, long durationMs) {
        long fallidos = resultados.stream().filter(ok -> !ok).count();

        if (resultados.isEmpty()) {
            return Mono.error(new IllegalStateException("No hay analizadores configurados"));
        }
        if (fallidos == resultados.size()) {
            return Mono.error(new AllAnalyzersFailedException(
                    "Fallaron los " + fallidos + " analizadores; el resultado no es fiable"));
        }
        String partial = fallidos > 0 ? "PARTIAL_ANALYSIS" : null;
        return finish(record, workspace, total, nuevos, durationMs, partial, fallidos);
    }

    private Mono<Boolean> runAnalyzer(Analyzer analyzer, ScanContext context,
                                      AtomicInteger total, AtomicInteger nuevos) {
        long inicio = System.currentTimeMillis();
        AtomicInteger delAnalizador = new AtomicInteger();

        return analyzer.analyze(context)
                .timeout(ANALYZER_TIMEOUT)
                .concatMap(raw -> findings
                        .upsert(context.organizationId(), context.projectId(),
                                context.scanId(), analyzer.name(), raw)
                        .doOnNext(esNuevo -> {
                            delAnalizador.incrementAndGet();
                            total.incrementAndGet();
                            if (esNuevo) {
                                nuevos.incrementAndGet();
                            }
                        }))
                .then(Mono.defer(() -> findings
                        .resolveMissing(context.projectId(), context.scanId(), analyzer.name())
                        .doOnNext(resueltos -> {
                            if (resueltos > 0) {
                                log.info("{} hallazgos de {} marcados como resueltos",
                                        resueltos, analyzer.name());
                            }
                        })))
                .then(Mono.defer(() -> scans.saveAnalyzerResult(context.scanId(),
                        context.organizationId(), analyzer.name(), analyzer.version(),
                        "COMPLETED", delAnalizador.get(),
                        System.currentTimeMillis() - inicio, null)))
                .thenReturn(true)
                // Un analizador que falla no tumba el scan completo. El
                // esquema modela scan_results por analizador precisamente
                // para esto: si Trivy cae, los hallazgos de Semgrep siguen
                // valiendo.
                .onErrorResume(e -> {
                    log.error("El analizador {} fallo en el scan {}: {}",
                            analyzer.name(), context.scanId(), e.getMessage());
                    return scans.saveAnalyzerResult(context.scanId(),
                                    context.organizationId(), analyzer.name(), analyzer.version(),
                                    "FAILED", delAnalizador.get(),
                                    System.currentTimeMillis() - inicio, rootMessage(e))
                            .thenReturn(false);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> finish(ScanStateRepository.ScanRecord record, ScanWorkspace workspace,
                              int total, int nuevos, long durationMs, String errorCode,
                              long fallidos) {
        if (errorCode != null) {
            log.warn("Scan {} completado parcialmente: {} analizadores fallaron",
                    record.scanId(), fallidos);
        }
        // El commit real solo se conoce despues de clonar: es el estado exacto
        // de la rama que se analizo, no el que tenia al pedir el scan.
        return scans.complete(record.scanId(), workspace.commitSha(), errorCode)
                // El score se calcula DESPUES de cerrar el scan y no bloquea su
                // cierre: si el calculo falla, el scan y sus hallazgos siguen
                // siendo validos, y la siguiente ejecucion recalculara. Al
                // reves, un error aqui dejaria el scan colgado en RUNNING
                // pese a haberse analizado entero.
                .then(scoreService.calculateAndStore(record.organizationId(),
                                record.projectId(), record.scanId(), record.startedAt())
                        .doOnError(e -> log.error("No se pudo calcular el score de {}: {}",
                                record.projectId(), e.getMessage()))
                        .onErrorResume(e -> Mono.empty()))
                .then(events.publish(DevGuardTopics.SCAN_COMPLETED,
                        record.organizationId().toString(),
                        ScanLifecycleEvent.completed(record.scanId(),
                                record.organizationId(), record.projectId(),
                                total, durationMs)))
                .doOnSuccess(v -> log.info(
                        "Scan {} completado en {} ms: {} hallazgos, {} nuevos",
                        record.scanId(), durationMs, total, nuevos));
    }

    private Mono<Void> handleFailure(ScanRequestedEvent event, Throwable error) {
        String code = error instanceof SecurityException ? "UNAUTHORIZED_REPOSITORY"
                : error instanceof AllAnalyzersFailedException ? "ALL_ANALYZERS_FAILED"
                : error instanceof com.devguard.worker.workspace
                .GitWorkspacePreparer.CloneException ? "CLONE_FAILED"
                : error instanceof com.devguard.worker.analyzer.process
                .ProcessRunner.ProcessTimeoutException ? "TIMEOUT"
                : error instanceof java.util.concurrent.TimeoutException ? "TIMEOUT"
                : "ANALYSIS_ERROR";

        log.error("Scan {} fallido ({}): {}", event.scanId(), code, error.getMessage());

        return scans.fail(event.scanId(), code, error.getMessage())
                .then(events.publish(DevGuardTopics.SCAN_FAILED,
                        event.organizationId().toString(),
                        ScanLifecycleEvent.failed(event.scanId(), event.organizationId(),
                                event.projectId(), code, error.getMessage())));
    }

    /**
     * Las excepciones de R2DBC suelen envolver la causa real varias capas mas
     * abajo. Guardar solo el mensaje de fuera deja en scan_results textos como
     * "executeMany; SQL [...]" que no explican nada.
     */
    private static String rootMessage(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String msg = root.getMessage() != null ? root.getMessage() : root.toString();
        return root == e ? msg : e.getClass().getSimpleName() + ": " + msg;
    }

    static final class AllAnalyzersFailedException extends RuntimeException {
        AllAnalyzersFailedException(String message) {
            super(message);
        }
    }
}
