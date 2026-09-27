package com.devguard.worker.finding;

import com.devguard.worker.AbstractWorkerIntegrationTest;
import com.devguard.worker.analyzer.RawFinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deduplicacion, regresiones y resolucion de hallazgos.
 *
 * Es la logica que convierte una lista de problemas en un historial util. Si
 * se rompe, cada scan duplica los mismos hallazgos, el Security Score se
 * vuelve ruido y el producto deja de poder responder que ha cambiado desde la
 * ultima vez, que es justo lo que promete.
 *
 * Y se rompe en silencio: nada falla, solo aparecen numeros mas altos.
 */
@DisplayName("Persistencia de hallazgos")
class FindingWriterTest extends AbstractWorkerIntegrationTest {

    @Autowired
    FindingWriter writer;

    @Autowired
    DatabaseClient db;

    private UUID organizationId;
    private UUID projectId;

    @BeforeEach
    void setUp() {
        // Un proyecto nuevo por prueba: comparten la base y un proyecto fijo
        // haria que cada metodo viera los hallazgos del anterior.
        organizationId = insertOrganization("org-" + System.nanoTime());
        projectId = insertProject(organizationId, "proj-" + System.nanoTime());
    }

    @Test
    @DisplayName("el primer hallazgo se inserta como nuevo")
    void primeraVezEsNuevo() {
        UUID scan = insertScan();

        Boolean nuevo = writer.upsert(organizationId, projectId, scan, "DEPENDENCY",
                dependency("xstream", "1.4.5", "CVE-2013-7285")).block();

        assertThat(nuevo).isTrue();
        assertThat(countFindings()).isEqualTo(1);
    }

    /**
     * El caso que se verifico a mano sobre WebGoat: el segundo scan del mismo
     * repositorio debe dar cero hallazgos nuevos. Si diera los mismos que el
     * primero, el fingerprint no esta deduplicando.
     */
    @Test
    @DisplayName("el mismo hallazgo en un segundo scan no es nuevo")
    void segundoScanNoDuplica() {
        RawFinding hallazgo = dependency("xstream", "1.4.5", "CVE-2013-7285");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY", hallazgo).block();

        UUID segundo = insertScan();
        Boolean nuevo = writer.upsert(organizationId, projectId, segundo, "DEPENDENCY",
                hallazgo).block();

        assertThat(nuevo).isFalse();
        assertThat(countFindings()).isEqualTo(1);
    }

    @Test
    @DisplayName("el segundo scan actualiza last_seen en lugar de insertar")
    void actualizaUltimaVezVisto() {
        RawFinding hallazgo = dependency("xstream", "1.4.5", "CVE-2013-7285");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY", hallazgo).block();

        UUID segundo = insertScan();
        writer.upsert(organizationId, projectId, segundo, "DEPENDENCY", hallazgo).block();

        UUID ultimoScan = queryUuid(
                "SELECT last_seen_scan_id FROM security_findings WHERE project_id = $1",
                projectId);
        UUID primerScan = queryUuid(
                "SELECT first_seen_scan_id FROM security_findings WHERE project_id = $1",
                projectId);

        assertThat(ultimoScan).isEqualTo(segundo);
        assertThat(primerScan)
                .as("el primer scan que lo vio no debe cambiar")
                .isEqualTo(primero);
    }

    /**
     * El fingerprint se calcula sobre analizador, regla, ruta y simbolo, nunca
     * sobre la linea. Si incluyera la linea, anadir un import al principio del
     * archivo desplazaria todo y los mismos hallazgos reaparecerian como nuevos
     * en cada scan.
     */
    @Test
    @DisplayName("mover el codigo no crea un hallazgo nuevo")
    void lineaNoAfectaLaIdentidad() {
        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "SAST",
                code("java.sql-injection", "src/UserRepo.java", 40)).block();

        UUID segundo = insertScan();
        Boolean nuevo = writer.upsert(organizationId, projectId, segundo, "SAST",
                code("java.sql-injection", "src/UserRepo.java", 180)).block();

        assertThat(nuevo).isFalse();
        assertThat(countFindings()).isEqualTo(1);

        Integer linea = queryInt(
                "SELECT line_start FROM security_findings WHERE project_id = $1", projectId);
        assertThat(linea)
                .as("la linea si se actualiza: es donde hay que ir a mirar")
                .isEqualTo(180);
    }

    @Test
    @DisplayName("hallazgos de paquetes distintos son hallazgos distintos")
    void paquetesDistintosNoSeMezclan() {
        UUID scan = insertScan();

        writer.upsert(organizationId, projectId, scan, "DEPENDENCY",
                dependency("xstream", "1.4.5", "CVE-1")).block();
        writer.upsert(organizationId, projectId, scan, "DEPENDENCY",
                dependency("log4j-core", "2.14.1", "CVE-2")).block();

        assertThat(countFindings()).isEqualTo(2);
    }

    // ------------------------------------------------------------ resolucion

    @Test
    @DisplayName("un hallazgo que ya no aparece se marca como resuelto")
    void resuelveLosQueDesaparecen() {
        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY",
                dependency("xstream", "1.4.5", "CVE-1")).block();

        // Segundo scan: el analizador corre pero ya no encuentra ese hallazgo.
        UUID segundo = insertScan();
        Long resueltos = writer.resolveMissing(projectId, segundo, "DEPENDENCY").block();

        assertThat(resueltos).isEqualTo(1L);
        assertThat(status()).isEqualTo("RESOLVED");
    }

    /**
     * Solo se resuelven los hallazgos del analizador que realmente corrio. Si
     * Trivy fallo en este scan, sus hallazgos no pueden darse por resueltos: no
     * se sabe si siguen ahi, y decir que estan arreglados seria un falso
     * limpio.
     */
    @Test
    @DisplayName("no se resuelven los hallazgos de otro analizador")
    void noResuelveLoDeOtroAnalizador() {
        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY",
                dependency("xstream", "1.4.5", "CVE-1")).block();

        UUID segundo = insertScan();
        Long resueltos = writer.resolveMissing(projectId, segundo, "SAST").block();

        assertThat(resueltos).isZero();
        assertThat(status()).isEqualTo("OPEN");
    }

    @Test
    @DisplayName("un hallazgo que sigue apareciendo no se resuelve")
    void noResuelveLoQueSigueAhi() {
        RawFinding hallazgo = dependency("xstream", "1.4.5", "CVE-1");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY", hallazgo).block();

        UUID segundo = insertScan();
        writer.upsert(organizationId, projectId, segundo, "DEPENDENCY", hallazgo).block();
        Long resueltos = writer.resolveMissing(projectId, segundo, "DEPENDENCY").block();

        assertThat(resueltos).isZero();
        assertThat(status()).isEqualTo("OPEN");
    }

    // ------------------------------------------------------------ regresiones

    /**
     * Un problema que reaparece despues de arreglarse dice algo sobre el
     * proceso del equipo que uno nunca arreglado no dice. Por eso vuelve como
     * REGRESSED y no como OPEN.
     */
    @Test
    @DisplayName("un hallazgo resuelto que reaparece vuelve como REGRESSED")
    void detectaRegresion() {
        RawFinding hallazgo = dependency("xstream", "1.4.5", "CVE-1");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY", hallazgo).block();

        UUID segundo = insertScan();
        writer.resolveMissing(projectId, segundo, "DEPENDENCY").block();
        assertThat(status()).isEqualTo("RESOLVED");

        UUID tercero = insertScan();
        writer.upsert(organizationId, projectId, tercero, "DEPENDENCY", hallazgo).block();

        assertThat(status()).isEqualTo("REGRESSED");
        assertThat(queryString(
                "SELECT resolved_at::text FROM security_findings WHERE project_id = $1",
                projectId))
                .as("al reaparecer deja de estar resuelto")
                .isNull();
    }

    /**
     * FALSE_POSITIVE y ACCEPTED_RISK son decisiones humanas. Si cada scan las
     * revirtiera, el analista tendria que descartar el mismo falso positivo
     * para siempre y acabaria ignorando la herramienta.
     */
    @Test
    @DisplayName("un scan no revierte un FALSE_POSITIVE")
    void respetaFalsoPositivo() {
        RawFinding hallazgo = secret(".env", "aws-key");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "SECRET", hallazgo).block();
        setStatus("FALSE_POSITIVE");

        UUID segundo = insertScan();
        writer.upsert(organizationId, projectId, segundo, "SECRET", hallazgo).block();

        assertThat(status()).isEqualTo("FALSE_POSITIVE");
    }

    @Test
    @DisplayName("un scan no revierte un ACCEPTED_RISK")
    void respetaRiesgoAceptado() {
        RawFinding hallazgo = dependency("xstream", "1.4.5", "CVE-1");

        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "DEPENDENCY", hallazgo).block();
        setStatus("ACCEPTED_RISK");

        UUID segundo = insertScan();
        writer.upsert(organizationId, projectId, segundo, "DEPENDENCY", hallazgo).block();

        assertThat(status()).isEqualTo("ACCEPTED_RISK");
    }

    @Test
    @DisplayName("un descartado tampoco se resuelve al desaparecer")
    void noResuelveDescartados() {
        UUID primero = insertScan();
        writer.upsert(organizationId, projectId, primero, "SECRET",
                secret(".env", "aws-key")).block();
        setStatus("FALSE_POSITIVE");

        UUID segundo = insertScan();
        writer.resolveMissing(projectId, segundo, "SECRET").block();

        assertThat(status()).isEqualTo("FALSE_POSITIVE");
    }

    // -------------------------------------------------------- clave de grupo

    @Test
    @DisplayName("el upsert escribe la clave de remediacion")
    void escribeClaveDeRemediacion() {
        UUID scan = insertScan();
        writer.upsert(organizationId, projectId, scan, "DEPENDENCY",
                dependency("xstream", "1.4.5", "CVE-1")).block();

        assertThat(queryString(
                "SELECT remediation_key FROM security_findings WHERE project_id = $1",
                projectId))
                .isEqualTo("dependency:xstream");
    }

    @Test
    @DisplayName("varios CVE del mismo paquete comparten clave y forman un grupo")
    void variosCveUnGrupo() {
        UUID scan = insertScan();

        for (int i = 0; i < 5; i++) {
            writer.upsert(organizationId, projectId, scan, "DEPENDENCY",
                    dependency("xstream", "1.4.5", "CVE-2021-" + (39100 + i))).block();
        }

        assertThat(countFindings()).isEqualTo(5);
        assertThat(queryLong("""
                SELECT count(DISTINCT remediation_key) FROM security_findings
                 WHERE project_id = $1
                """, projectId))
                .as("cinco hallazgos, una sola accion")
                .isEqualTo(1L);
    }

    // ------------------------------------------------------------- utilidades

    private RawFinding dependency(String pkg, String version, String cve) {
        return new RawFinding("DEPENDENCY", "HIGH", cve + " en " + pkg, "descripcion",
                "Actualizar", cve, "CWE-502", cve, 7.5, "pom.xml", null, null,
                null, pkg, version, "9.9.9", pkg);
    }

    private RawFinding code(String ruleId, String path, int line) {
        return new RawFinding("VULNERABILITY", "HIGH", "Inyeccion SQL", "descripcion",
                "Usar consultas parametrizadas", ruleId, "CWE-89", null, null,
                path, line, line, null, null, null, null, "findByName");
    }

    private RawFinding secret(String path, String ruleId) {
        return new RawFinding("SECRET", "HIGH", "Credencial detectada", "descripcion",
                "Rotar", ruleId, "CWE-798", null, null, path, 1, 1,
                "AKIA****", null, null, null, ruleId);
    }

    private UUID insertOrganization(String slug) {
        return db.sql("""
                INSERT INTO organizations (slug, name, plan, max_projects, max_users)
                VALUES (:slug, :slug, 'TEAM', 100, 100) RETURNING id
                """)
                .bind("slug", slug)
                .map((row, meta) -> row.get("id", UUID.class))
                .one().block();
    }

    private UUID insertProject(UUID orgId, String slug) {
        return db.sql("""
                INSERT INTO projects (organization_id, name, slug)
                VALUES (:orgId, :slug, :slug) RETURNING id
                """)
                .bind("orgId", orgId)
                .bind("slug", slug)
                .map((row, meta) -> row.get("id", UUID.class))
                .one().block();
    }

    private UUID insertScan() {
        return db.sql("""
                INSERT INTO scans (organization_id, project_id, status, idempotency_key)
                VALUES (:orgId, :projectId, 'RUNNING', :key) RETURNING id
                """)
                .bind("orgId", organizationId)
                .bind("projectId", projectId)
                .bind("key", UUID.randomUUID().toString())
                .map((row, meta) -> row.get("id", UUID.class))
                .one().block();
    }

    private void setStatus(String status) {
        db.sql("UPDATE security_findings SET status = :status, validation_state = 'VALIDATED' "
                        + "WHERE project_id = :projectId")
                .bind("status", status)
                .bind("projectId", projectId)
                .fetch().rowsUpdated().block();
    }

    private String status() {
        return queryString(
                "SELECT status FROM security_findings WHERE project_id = $1", projectId);
    }

    private Long countFindings() {
        return queryLong(
                "SELECT count(*) FROM security_findings WHERE project_id = $1", projectId);
    }

    private String queryString(String sql, UUID param) {
        return db.sql(sql).bind(0, param)
                .map((row, meta) -> Optional.ofNullable(row.get(0, String.class)))
                .one()
                .blockOptional()
                .map(opt -> opt.orElse(null))
                .orElse(null);
    }

    private Integer queryInt(String sql, UUID param) {
        return db.sql(sql).bind(0, param)
                .map((row, meta) -> row.get(0, Integer.class))
                .one().block();
    }

    private Long queryLong(String sql, UUID param) {
        return db.sql(sql).bind(0, param)
                .map((row, meta) -> row.get(0, Long.class))
                .one().block();
    }

    private UUID queryUuid(String sql, UUID param) {
        return db.sql(sql).bind(0, param)
                .map((row, meta) -> row.get(0, UUID.class))
                .one().block();
    }
}
