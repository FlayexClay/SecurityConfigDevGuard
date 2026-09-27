package com.devguard.worker.finding;

import com.devguard.worker.analyzer.RawFinding;
import com.devguard.worker.analyzer.RemediationKey;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
public class FindingWriter {

    private final DatabaseClient db;

    public FindingWriter(DatabaseClient db) {
        this.db = db;
    }

    public Mono<Boolean> upsert(UUID organizationId, UUID projectId, UUID scanId,
                                String analyzer, RawFinding f) {
        String fingerprint = f.fingerprint(analyzer);

        return db.sql("""
                INSERT INTO security_findings (
                    organization_id, project_id, first_seen_scan_id, last_seen_scan_id,
                    category, severity, raw_severity, title, description, recommendation,
                    fingerprint, analyzer, rule_id, cwe, cve, cvss_score,
                    file_path, line_start, line_end, evidence,
                    package_name, installed_version, fixed_version,
                    status, validation_state, priority, remediation_key,
                    first_seen_at, last_seen_at)
                VALUES (
                    :organizationId, :projectId, :firstSeenScanId, :lastSeenScanId,
                    :category, :severity, :rawSeverity, :title, :description, :recommendation,
                    :fingerprint, :analyzer, :ruleId, :cwe, :cve, :cvssScore,
                    :filePath, :lineStart, :lineEnd, :evidence,
                    :packageName, :installedVersion, :fixedVersion,
                    'OPEN', 'UNVALIDATED', :priority, :remediationKey,
                    now(), now())
                ON CONFLICT (project_id, fingerprint) DO UPDATE
                   SET last_seen_scan_id = EXCLUDED.last_seen_scan_id,
                       last_seen_at = now(),
                       severity = EXCLUDED.severity,
                       cvss_score = EXCLUDED.cvss_score,
                       fixed_version = EXCLUDED.fixed_version,
                       line_start = EXCLUDED.line_start,
                       line_end = EXCLUDED.line_end,
                       status = CASE
                           WHEN security_findings.status = 'RESOLVED' THEN 'REGRESSED'
                           WHEN security_findings.status IN ('FALSE_POSITIVE', 'ACCEPTED_RISK')
                                THEN security_findings.status
                           ELSE security_findings.status
                       END,
                       resolved_at = CASE
                           WHEN security_findings.status = 'RESOLVED' THEN NULL
                           ELSE security_findings.resolved_at
                       END
                RETURNING (xmax = 0) AS inserted
                """)
                // Nombres distintos aunque el valor sea el mismo. Con un
                // parametro con nombre repetido (:scanId, :scanId) la
                // traduccion a marcadores posicionales de PostgreSQL ($1,
                // $2...) se desalinea y el parametro siguiente queda sin
                // enlazar: el error resultante ("No parameter specified for
                // [title]") senala a un parametro que si esta enlazado.
                .bind("organizationId", organizationId)
                .bind("projectId", projectId)
                .bind("firstSeenScanId", scanId)
                .bind("lastSeenScanId", scanId)
                .bind("category", f.category())
                .bind("severity", f.severity())
                .bind("rawSeverity", f.severity())
                .bind("title", f.title())
                .bind("description", nullable(f.description()))
                .bind("recommendation", nullable(f.recommendation()))
                .bind("fingerprint", fingerprint)
                .bind("analyzer", analyzer)
                .bind("ruleId", nullable(f.ruleId()))
                .bind("cwe", nullable(f.cwe()))
                .bind("cve", nullable(f.cve()))
                .bind("cvssScore", f.cvssScore() != null
                        ? Parameter.from(f.cvssScore()) : Parameter.empty(Double.class))
                .bind("filePath", nullable(f.filePath()))
                .bind("lineStart", f.lineStart() != null
                        ? Parameter.from(f.lineStart()) : Parameter.empty(Integer.class))
                .bind("lineEnd", f.lineEnd() != null
                        ? Parameter.from(f.lineEnd()) : Parameter.empty(Integer.class))
                .bind("evidence", nullable(f.evidence()))
                .bind("packageName", nullable(f.packageName()))
                .bind("installedVersion", nullable(f.installedVersion()))
                .bind("fixedVersion", nullable(f.fixedVersion()))
                .bind("priority", priorityOf(f.severity()))
                .bind("remediationKey", RemediationKey.of(analyzer, f))
                // xmax = 0 distingue un INSERT real de un UPDATE dentro de un
                // upsert. Es un detalle propio de PostgreSQL, pero evita una
                // consulta previa de existencia por cada hallazgo.
                .map((row, meta) -> Boolean.TRUE.equals(row.get("inserted", Boolean.class)))
                .one()
                .defaultIfEmpty(false);
    }

    /**
     * Cierra los hallazgos que este scan ya no encontro.
     *
     * Solo toca los que estaban abiertos y pertenecen a analizadores que
     * realmente corrieron. Si Trivy fallo en este scan, sus hallazgos no deben
     * darse por resueltos: no se sabe si siguen ahi.
     */
    public Mono<Long> resolveMissing(UUID projectId, UUID scanId, String analyzer) {
        return db.sql("""
                        UPDATE security_findings
                           SET status = 'RESOLVED', resolved_at = now()
                         WHERE project_id = :projectId
                           AND analyzer = :analyzer
                           AND status IN ('OPEN', 'CONFIRMED', 'REGRESSED')
                           AND (last_seen_scan_id IS DISTINCT FROM :scanId)
                        """)
                .bind("projectId", projectId)
                .bind("scanId", scanId)
                .bind("analyzer", analyzer)
                .fetch().rowsUpdated();
    }

    private static int priorityOf(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            default -> 4;
        };
    }

    private static Object nullable(String value) {
        return value != null ? Parameter.from(value) : Parameter.empty(String.class);
    }
}
