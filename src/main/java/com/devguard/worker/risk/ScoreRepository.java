package com.devguard.worker.risk;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Repository
public class ScoreRepository {

    private final DatabaseClient db;
    private final ObjectMapper mapper;

    public ScoreRepository(DatabaseClient db, ObjectMapper eventObjectMapper) {
        this.db = db;
        this.mapper = eventObjectMapper;
    }

    /**
     * Carga solo los campos que el calculo necesita.
     *
     * Traer la entidad completa significaria arrastrar descripciones y
     * evidencias de cientos de hallazgos a un worker con 384 MB de heap, para
     * despues no usarlas.
     */
    public Flux<FindingSnapshot> loadForScoring(UUID projectId) {
        return db.sql("""
                SELECT id, category, severity, status, file_path, fixed_version,
                       cvss_score, remediation_key,
                       EXTRACT(DAY FROM (now() - first_seen_at))::bigint AS age_days
                  FROM security_findings
                 WHERE project_id = :projectId
                   AND status IN ('OPEN', 'CONFIRMED', 'REGRESSED')
                """)
                .bind("projectId", projectId)
                .map((row, meta) -> new FindingSnapshot(
                        row.get("id", UUID.class),
                        row.get("category", String.class),
                        row.get("severity", String.class),
                        row.get("status", String.class),
                        row.get("file_path", String.class),
                        row.get("fixed_version", String.class),
                        row.get("cvss_score", java.math.BigDecimal.class) != null
                                ? row.get("cvss_score", java.math.BigDecimal.class).doubleValue()
                                : null,
                        row.get("age_days", Long.class) != null
                                ? row.get("age_days", Long.class) : 0L,
                        row.get("remediation_key", String.class)))
                .all();
    }

    /** Hallazgos vistos por primera vez en este scan. */
    public Mono<Integer> countNewInScan(UUID projectId, UUID scanId) {
        return db.sql("""
                SELECT count(*)::int AS n FROM security_findings
                 WHERE project_id = :projectId AND first_seen_scan_id = :scanId
                """)
                .bind("projectId", projectId)
                .bind("scanId", scanId)
                .map((row, meta) -> row.get("n", Integer.class))
                .one()
                .defaultIfEmpty(0);
    }

    /** Hallazgos que este scan cerro. */
    public Mono<Integer> countResolvedInScan(UUID projectId, OffsetDateTime since) {
        return db.sql("""
                SELECT count(*)::int AS n FROM security_findings
                 WHERE project_id = :projectId
                   AND status = 'RESOLVED'
                   AND resolved_at >= :since
                """)
                .bind("projectId", projectId)
                .bind("since", since)
                .map((row, meta) -> row.get("n", Integer.class))
                .one()
                .defaultIfEmpty(0);
    }

    public Mono<Integer> previousScore(UUID projectId) {
        return db.sql("""
                SELECT score FROM security_scores
                 WHERE project_id = :projectId
                 ORDER BY calculated_at DESC
                 LIMIT 1
                """)
                .bind("projectId", projectId)
                .map((row, meta) -> row.get("score", Integer.class))
                .one();
    }

    /**
     * La tabla es una serie historica, no un valor mutable: cada scan añade su
     * fila. La restriccion scores_uk sobre scan_id evita duplicados si el
     * mismo scan se reprocesara.
     */
    public Mono<Void> save(UUID organizationId, UUID projectId, UUID scanId,
                           ScoreResult result, Integer previousScore) {
        String breakdownJson;
        try {
            breakdownJson = mapper.writeValueAsString(result.breakdown());
        } catch (Exception e) {
            breakdownJson = "{}";
        }

        return db.sql("""
                INSERT INTO security_scores (
                    organization_id, project_id, scan_id, score, grade, previous_score,
                    critical_count, high_count, medium_count, low_count, info_count,
                    new_findings, resolved_findings, breakdown, algorithm_version)
                VALUES (
                    :organizationId, :projectId, :scanId, :score, :grade, :previousScore,
                    :critical, :high, :medium, :low, :info,
                    :newFindings, :resolvedFindings, CAST(:breakdown AS jsonb), 'v1')
                ON CONFLICT (scan_id) DO UPDATE
                   SET score = EXCLUDED.score,
                       grade = EXCLUDED.grade,
                       breakdown = EXCLUDED.breakdown,
                       calculated_at = now()
                """)
                .bind("organizationId", organizationId)
                .bind("projectId", projectId)
                .bind("scanId", scanId)
                .bind("score", result.score())
                .bind("grade", result.grade())
                .bind("previousScore", previousScore != null
                        ? Parameter.from(previousScore) : Parameter.empty(Integer.class))
                .bind("critical", result.counts().critical())
                .bind("high", result.counts().high())
                .bind("medium", result.counts().medium())
                .bind("low", result.counts().low())
                .bind("info", result.counts().info())
                .bind("newFindings", result.newFindings())
                .bind("resolvedFindings", result.resolvedFindings())
                .bind("breakdown", breakdownJson)
                .fetch().rowsUpdated().then();
    }

    /**
     * Fija la prioridad calculada en cada hallazgo.
     *
     * Es lo que permite que el dashboard ordene por impacto real y no por
     * severidad declarada, que es lo que pide el documento de diseño. Sin
     * esto, los tres falsos positivos de secretos en archivos de ejemplo
     * apareceria por encima de una dependencia critica con parche disponible.
     */
    public Mono<Void> updatePriorities(Map<UUID, Integer> priorities) {
        if (priorities.isEmpty()) {
            return Mono.empty();
        }
        return Flux.fromIterable(priorities.entrySet())
                .concatMap(e -> db.sql(
                                "UPDATE security_findings SET priority = :priority "
                                        + "WHERE id = :id")
                        .bind("priority", e.getValue())
                        .bind("id", e.getKey())
                        .fetch().rowsUpdated())
                .then();
    }
}
