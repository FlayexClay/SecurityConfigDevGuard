package com.devguard.worker.analyzer.trivy;

import com.devguard.worker.analyzer.*;
import com.devguard.worker.analyzer.process.ProcessRunner;
import com.devguard.worker.analyzer.semgrep.SemgrepAnalyzer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConditionalOnProperty(name = "devguard.worker.simulated", havingValue = "false")
public class TrivyAnalyzers {

    private static final String VERSION = "trivy";

    @Bean
    public Analyzer trivyDependencyAnalyzer(TrivyRunner trivy) {
        return new Analyzer() {
            @Override
            public String name() {
                return "DEPENDENCY";
            }

            @Override
            public String version() {
                return VERSION;
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return trivy.scan(context.workspace(), "vuln")
                        .flatMapMany(root -> Flux.fromIterable(parseVulnerabilities(root)));
            }
        };
    }

    @Bean
    public Analyzer trivySecretAnalyzer(TrivyRunner trivy) {
        return new Analyzer() {
            @Override
            public String name() {
                return "SECRET";
            }

            @Override
            public String version() {
                return VERSION;
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return trivy.scan(context.workspace(), "secret")
                        .flatMapMany(root -> Flux.fromIterable(parseSecrets(root)));
            }
        };
    }

    @Bean
    public Analyzer trivyConfigAnalyzer(TrivyRunner trivy) {
        return new Analyzer() {
            @Override
            public String name() {
                return "CONFIG";
            }

            @Override
            public String version() {
                return VERSION;
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return trivy.scan(context.workspace(), "misconfig")
                        .flatMapMany(root -> Flux.fromIterable(parseMisconfigurations(root)));
            }
        };
    }

    /**
     * Semgrep se declara aqui, dentro de la configuracion que ya exige
     * simulated=false. Como @Component se habria registrado tambien en modo
     * simulado, y habria intentado analizar un workspace que no existe.
     */
    @Bean
    @ConditionalOnProperty(name = "devguard.worker.sast.enabled", havingValue = "true",
            matchIfMissing = true)
    public Analyzer semgrepAnalyzer(
            ProcessRunner runner,
            ObjectMapper eventObjectMapper,
            @Value("${devguard.worker.sast.rules:/opt/semgrep-rules}") String rulesPath,
            @Value("${devguard.worker.sast.timeout-minutes:15}") long timeoutMinutes,
            @Value("${devguard.worker.sast.jobs:2}") int jobs,
            @Value("${devguard.worker.sast.scope-rules:true}") boolean scopeRules) {
        return new SemgrepAnalyzer(runner, eventObjectMapper, rulesPath,
                timeoutMinutes, jobs, scopeRules);
    }

    static List<RawFinding> parseVulnerabilities(JsonNode root) {
        List<RawFinding> findings = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = result.path("Target").asText(null);
            for (JsonNode v : result.path("Vulnerabilities")) {
                String cve = text(v, "VulnerabilityID");
                String pkg = text(v, "PkgName");
                findings.add(new RawFinding(
                        "DEPENDENCY",
                        Severities.fromTrivy(text(v, "Severity")),
                        titleOrFallback(text(v, "Title"), cve, pkg),
                        text(v, "Description"),
                        fixRecommendation(text(v, "FixedVersion"), pkg),
                        cve,
                        firstCwe(v.path("CweIDs")),
                        cve != null && cve.startsWith("CVE-") ? cve : null,
                        cvss(v),
                        target,
                        null, null, null,
                        pkg,
                        text(v, "InstalledVersion"),
                        text(v, "FixedVersion"),
                        // El simbolo del fingerprint es el paquete, no la
                        // ruta del manifiesto: el mismo paquete vulnerable
                        // declarado en dos modulos es el mismo problema.
                        pkg));
            }
        }
        return findings;
    }

    static List<RawFinding> parseSecrets(JsonNode root) {
        List<RawFinding> findings = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = result.path("Target").asText(null);
            for (JsonNode s : result.path("Secrets")) {
                String ruleId = text(s, "RuleID");
                findings.add(new RawFinding(
                        "SECRET",
                        Severities.fromTrivy(text(s, "Severity")),
                        text(s, "Title") != null
                                ? text(s, "Title")
                                : "Credencial detectada (" + ruleId + ")",
                        "Se detecto una credencial en el control de versiones.",
                        "Revocar y rotar la credencial, y moverla a un gestor de secretos. "
                                + "Rotar aunque el repositorio sea privado: el historial de git "
                                + "conserva el valor.",
                        ruleId,
                        "CWE-798",
                        null,
                        null,
                        target,
                        intOrNull(s, "StartLine"),
                        intOrNull(s, "EndLine"),
                        // El valor completo NUNCA se persiste.
                        Redaction.maskSecret(text(s, "Match")),
                        null, null, null,
                        ruleId));
            }
        }
        return findings;
    }

    static List<RawFinding> parseMisconfigurations(JsonNode root) {
        List<RawFinding> findings = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = result.path("Target").asText(null);
            for (JsonNode m : result.path("Misconfigurations")) {
                String id = text(m, "ID");
                JsonNode cause = m.path("CauseMetadata");
                findings.add(new RawFinding(
                        "MISCONFIGURATION",
                        Severities.fromTrivy(text(m, "Severity")),
                        text(m, "Title") != null ? text(m, "Title") : id,
                        text(m, "Description") != null
                                ? text(m, "Description")
                                : text(m, "Message"),
                        text(m, "Resolution"),
                        id,
                        null, null, null,
                        target,
                        intOrNull(cause, "StartLine"),
                        intOrNull(cause, "EndLine"),
                        Redaction.truncateCode(text(m, "Message")),
                        null, null, null,
                        id));
            }
        }
        return findings;
    }

    private static String titleOrFallback(String title, String cve, String pkg) {
        if (title != null && !title.isBlank()) {
            return title;
        }
        return (cve != null ? cve : "Vulnerabilidad") + " en " + (pkg != null ? pkg : "dependencia");
    }

    private static String fixRecommendation(String fixedVersion, String pkg) {
        if (fixedVersion == null || fixedVersion.isBlank()) {
            // Distinguir esto importa: no es lo mismo "no has actualizado" que
            // "todavia no hay parche".
            return "No hay version corregida publicada. Evaluar mitigaciones o "
                    + "sustituir la dependencia.";
        }
        return "Actualizar " + (pkg != null ? pkg : "la dependencia") + " a " + fixedVersion + ".";
    }

    private static Double cvss(JsonNode v) {
        JsonNode cvss = v.path("CVSS");
        // Trivy devuelve las puntuaciones de varias fuentes (nvd, redhat...).
        // Se prefiere nvd por consistencia entre scans.
        for (String source : List.of("nvd", "redhat", "ghsa")) {
            JsonNode node = cvss.path(source);
            if (node.has("V3Score")) {
                return node.get("V3Score").asDouble();
            }
            if (node.has("V2Score")) {
                return node.get("V2Score").asDouble();
            }
        }
        var names = cvss.fieldNames();
        while (names.hasNext()) {
            JsonNode node = cvss.path(names.next());
            if (node.has("V3Score")) {
                return node.get("V3Score").asDouble();
            }
        }
        return null;
    }

    private static String firstCwe(JsonNode cwes) {
        return cwes.isArray() && !cwes.isEmpty() ? cwes.get(0).asText(null) : null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String s = value.asText();
        return s.isBlank() ? null : s;
    }

    private static Integer intOrNull(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isInt() && value.asInt() > 0 ? value.asInt() : null;
    }
}
