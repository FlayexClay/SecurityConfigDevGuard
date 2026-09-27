package com.devguard.worker.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.util.UUID;

@Repository
public class ScanStateRepository {

    private static final Logger log = LoggerFactory.getLogger(ScanStateRepository.class);


    private final DatabaseClient db;

    public ScanStateRepository(DatabaseClient db) {
        this.db = db;
    }

    /**
     * Reclama el scan para este worker. Devuelve true solo si lo consiguio.
     *
     * Esta es la idempotencia real del sistema. Kafka entrega at-least-once,
     * asi que los mensajes duplicados no son una anomalia sino lo esperado.
     * La clausula WHERE exige que el scan siga en REQUESTED o QUEUED: si otro
     * worker ya lo tomo, o si es una reentrega de un scan terminado, la
     * actualizacion afecta cero filas y el mensaje se descarta.
     *
     * La atomicidad la garantiza PostgreSQL con un solo UPDATE; no hace falta
     * bloqueo explicito ni coordinacion entre workers.
     */
    public Mono<Boolean> claim(UUID scanId) {
        return db.sql("""
                UPDATE scans
                   SET status = 'RUNNING', started_at = now()
                 WHERE id = :id
                   AND status IN ('REQUESTED', 'QUEUED')
                """)
                .bind("id", scanId)
                .fetch()
                .rowsUpdated()
                .map(rows -> rows > 0)
                .defaultIfEmpty(false);
    }

    public Mono<ScanRecord> load(UUID scanId) {
        return db.sql("""
                SELECT s.id, s.organization_id, s.project_id, s.repository_id,
                       s.branch, s.started_at, r.clone_url, r.default_branch,
                       r.authorized
                  FROM scans s
                  LEFT JOIN repositories r ON r.id = s.repository_id
                 WHERE s.id = :id
                """)
                .bind("id", scanId)
                .map((row, meta) -> new ScanRecord(
                        row.get("id", UUID.class),
                        row.get("organization_id", UUID.class),
                        row.get("project_id", UUID.class),
                        row.get("repository_id", UUID.class),
                        row.get("clone_url", String.class),
                        row.get("branch", String.class),
                        row.get("started_at", OffsetDateTime.class),
                        Boolean.TRUE.equals(row.get("authorized", Boolean.class))))
                .one();
    }

    /**
     * errorCode no nulo con estado COMPLETED significa analisis parcial: el
     * scan dio resultados utiles, pero no todos los analizadores corrieron.
     * El dashboard debe mostrarlo, porque "sin hallazgos de dependencias"
     * no es lo mismo que "el analizador de dependencias no corrio".
     */
    public Mono<Void> complete(UUID scanId, String commitSha, String errorCode) {
        return db.sql("""
                UPDATE scans
                   SET status = 'COMPLETED',
                       finished_at = now(),
                       duration_ms = EXTRACT(EPOCH FROM (now() - started_at)) * 1000,
                       commit_sha = :commitSha,
                       error_code = :errorCode
                 WHERE id = :id AND status = 'RUNNING'
                """)
                .bind("id", scanId)
                .bind("commitSha", commitSha != null
                        ? Parameter.from(commitSha) : Parameter.empty(String.class))
                .bind("errorCode", errorCode != null
                        ? Parameter.from(errorCode) : Parameter.empty(String.class))
                .fetch().rowsUpdated()
                // Cero filas significa que alguien cambio el estado por
                // debajo. Antes fallaba en silencio y el scan quedaba en
                // QUEUED pese a haberse analizado entero.
                .doOnNext(filas -> {
                    if (filas == 0) {
                        log.warn("No se pudo cerrar el scan {}: ya no estaba en RUNNING",
                                scanId);
                    }
                })
                .then();
    }

    public Mono<Void> fail(UUID scanId, String errorCode, String errorMessage) {
        return db.sql("""
                UPDATE scans
                   SET status = 'FAILED',
                       finished_at = now(),
                       duration_ms = CASE WHEN started_at IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (now() - started_at)) * 1000 END,
                       error_code = :code,
                       error_message = :message
                 WHERE id = :id AND status NOT IN ('COMPLETED', 'CANCELLED')
                """)
                .bind("id", scanId)
                .bind("code", errorCode)
                .bind("message", truncate(errorMessage))
                .fetch().rowsUpdated().then();
    }

    public Mono<Void> saveAnalyzerResult(UUID scanId, UUID organizationId, String analyzer,
                                         String analyzerVersion, String status,
                                         int findingsCount, long durationMs,
                                         String errorMessage) {
        return db.sql("""
                INSERT INTO scan_results (
                    organization_id, scan_id, analyzer, analyzer_version, status,
                    findings_count, started_at, finished_at, duration_ms,
                    summary, error_message)
                VALUES (
                    :organizationId, :scanId, :analyzer, :analyzerVersion, :status,
                    :findingsCount, now() - make_interval(secs => :durationSecs), now(),
                    :durationMs, CAST(:summary AS jsonb), :errorMessage)
                ON CONFLICT (scan_id, analyzer) DO UPDATE
                   SET status = EXCLUDED.status,
                       findings_count = EXCLUDED.findings_count,
                       finished_at = EXCLUDED.finished_at,
                       duration_ms = EXCLUDED.duration_ms,
                       error_message = EXCLUDED.error_message
                """)
                .bind("organizationId", organizationId)
                .bind("scanId", scanId)
                .bind("analyzer", analyzer)
                .bind("analyzerVersion", analyzerVersion)
                .bind("status", status)
                .bind("findingsCount", findingsCount)
                .bind("durationSecs", durationMs / 1000.0)
                .bind("durationMs", durationMs)
                .bind("summary", "{\"findings\":" + findingsCount + "}")
                .bind("errorMessage", errorMessage != null
                        ? Parameter.from(truncate(errorMessage))
                        : Parameter.empty(String.class))
                .fetch().rowsUpdated().then();
    }

    private static String truncate(String s) {
        if (s == null) {
            return null;
        }
        return s.length() > 1000 ? s.substring(0, 1000) : s;
    }

    public record ScanRecord(
            UUID scanId,
            UUID organizationId,
            UUID projectId,
            UUID repositoryId,
            String cloneUrl,
            String branch,
            OffsetDateTime startedAt,
            boolean repositoryAuthorized) {
    }
}
