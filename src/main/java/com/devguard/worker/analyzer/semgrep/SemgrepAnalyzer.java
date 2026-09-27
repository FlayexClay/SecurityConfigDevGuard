package com.devguard.worker.analyzer.semgrep;

import com.devguard.worker.analyzer.*;
import com.devguard.worker.analyzer.process.ProcessRunner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SemgrepAnalyzer implements Analyzer {

    private static final Logger log = LoggerFactory.getLogger(SemgrepAnalyzer.class);

    private final ProcessRunner runner;
    private final ObjectMapper mapper;
    private final String rulesPath;
    private final Duration timeout;
    private final int jobs;
    private final boolean scopeRules;

    public SemgrepAnalyzer(
            ProcessRunner runner,
            ObjectMapper eventObjectMapper,
            @Value("${devguard.worker.sast.rules:/opt/semgrep-rules}") String rulesPath,
            @Value("${devguard.worker.sast.timeout-minutes:15}") long timeoutMinutes,
            @Value("${devguard.worker.sast.jobs:1}") int jobs,
            @Value("${devguard.worker.sast.scope-rules:true}") boolean scopeRules) {
        this.runner = runner;
        this.mapper = eventObjectMapper;
        this.rulesPath = rulesPath;
        this.timeout = Duration.ofMinutes(timeoutMinutes);
        this.jobs = jobs;
        this.scopeRules = scopeRules;
    }

    @Override
    public String name() {
        return "SAST";
    }

    @Override
    public String version() {
        return "semgrep";
    }

    /**
     * Acotar las reglas se puede desactivar con
     * DEVGUARD_SAST_SCOPE_RULES=false, para comparar o si la deteccion falla
     * en algun repositorio concreto.
     */
    private List<Path> resolveConfigs(ScanContext context) {
        Path root = Path.of(rulesPath);
        if (!scopeRules || context.workspace() == null) {
            return List.of(root);
        }
        return LanguageDetector.detectConfigs(context.workspace(), root);
    }

    @Override
    public Flux<RawFinding> analyze(ScanContext context) {
        List<String> command = new ArrayList<>(List.of("semgrep", "scan"));

        // Reglas acotadas a los lenguajes presentes. Reglas locales, nunca del
        // registro remoto: un scan no debe depender de que una descarga
        // externa funcione, y asi quedan fijadas a la version de la imagen.
        for (Path config : resolveConfigs(context)) {
            command.add("--config");
            command.add(config.toString());
        }

        command.addAll(List.of(
                "--json",
                "--quiet",
                // Se respeta .gitignore a proposito. Con --no-git-ignore
                // semgrep entra en directorios de compilacion y dependencias
                // descargadas, que no forman parte del codigo del proyecto y
                // multiplican el tiempo sin aportar hallazgos reales.
                "--exclude", "node_modules",
                "--exclude", "target",
                "--exclude", "build",
                "--exclude", "dist",
                "--exclude", "vendor",
                // Semgrep es el mayor consumidor de memoria del worker, pero
                // los analizadores corren en secuencia, asi que mientras este
                // trabajando tiene la maquina para el.
                "--jobs", String.valueOf(jobs),
                // Limite por archivo: un fichero generado de varios MB puede
                // hacer explotar el analisis de una sola regla.
                "--max-target-bytes", "2000000",
                // Que una regla se atasque en un archivo no debe tumbar el
                // analisis completo.
                "--timeout", "30",
                "--metrics", "off",
                "."));

        return runner.run(command, context.workspace(),
                        Map.of("SEMGREP_SEND_METRICS", "off"), timeout)
                .flatMap(result -> {
                    // Semgrep devuelve 1 cuando encuentra hallazgos, que es
                    // exito desde nuestro punto de vista. Solo 2 o mas es un
                    // error real.
                    if (result.exitCode() > 1) {
                        // El motivo del fallo viaja en el JSON de stdout, no
                        // en stderr: el array "errors" trae el archivo y la
                        // causa exactos. Quedarse solo con stderr deja un
                        // error_message vacio y a nadie sabiendo que paso.
                        String detalle = extractErrors(result.stdoutFile());
                        result.cleanup();
                        return Mono.error(new IllegalStateException(
                                "semgrep fallo (codigo " + result.exitCode() + "): "
                                        + (detalle != null ? detalle : result.stderr())));
                    }
                    try {
                        // Salida vacia NO es "no encontre nada": es que el
                        // proceso murio antes de escribir el JSON. Un
                        // traceback de Python sale por stderr y deja stdout a
                        // cero, y el codigo de salida puede seguir siendo 1.
                        // Tratarlo como exito daria un scan COMPLETED con cero
                        // hallazgos de SAST, que es indistinguible de un
                        // proyecto limpio: el peor resultado posible en una
                        // herramienta de seguridad.
                        long size = java.nio.file.Files.size(result.stdoutFile());
                        if (size == 0) {
                            return Mono.error(new IllegalStateException(
                                    "semgrep no produjo salida (codigo "
                                            + result.exitCode() + "): " + result.stderr()));
                        }
                        JsonNode root = mapper.readTree(result.stdoutFile().toFile());
                        // Sin el campo "results" no es una salida valida de
                        // semgrep, aunque sea JSON bien formado.
                        if (!root.has("results")) {
                            return Mono.error(new IllegalStateException(
                                    "la salida de semgrep no tiene el campo results"));
                        }
                        // Los errores internos de semgrep viajan dentro del
                        // propio JSON: reglas que no cargan, archivos que no
                        // parsean. No son fatales, pero hay que verlos.
                        int errores = root.path("errors").size();
                        if (errores > 0) {
                            // Un error de configuracion no es un error
                            // "interno" tolerable: significa que semgrep no
                            // cargo las reglas y no analizo nada. Se
                            // distingue por paths.scanned vacio.
                            boolean noAnalizoNada = root.path("paths").path("scanned").isEmpty();
                            if (noAnalizoNada) {
                                return Mono.error(new IllegalStateException(
                                        "semgrep no analizo ningun archivo: "
                                                + errorSummary(root)));
                            }
                            log.warn("semgrep reporto {} errores no fatales; el primero: {}",
                                    errores, errorSummary(root));
                        }
                        log.debug("semgrep termino en {} ms con {} resultados",
                                result.durationMs(), root.path("results").size());
                        return Mono.just(root);
                    } catch (Exception e) {
                        return Mono.error(new IllegalStateException(
                                "No se pudo leer la salida de semgrep: " + e.getMessage(), e));
                    } finally {
                        result.cleanup();
                    }
                })
                .flatMapMany(root -> Flux.fromIterable(parse(root)));
    }

    static List<RawFinding> parse(JsonNode root) {
        List<RawFinding> findings = new ArrayList<>();
        for (JsonNode r : root.path("results")) {
            JsonNode extra = r.path("extra");
            JsonNode metadata = extra.path("metadata");
            String checkId = text(r, "check_id");
            String path = text(r, "path");

            findings.add(new RawFinding(
                    categoryOf(checkId),
                    Severities.fromSemgrep(text(extra, "severity")),
                    shortTitle(text(extra, "message"), checkId),
                    text(extra, "message"),
                    text(metadata, "fix") != null
                            ? text(metadata, "fix")
                            : text(extra, "fix"),
                    checkId,
                    firstCwe(metadata.path("cwe")),
                    null,
                    null,
                    path,
                    intOrNull(r.path("start"), "line"),
                    intOrNull(r.path("end"), "line"),
                    // Las reglas de secretos de semgrep exponen la
                    // coincidencia en metavars; "lines" es la linea completa.
                    // Para un secreto hay que enmascarar la coincidencia: si
                    // se pasa la linea, la evidencia acaba conservando texto
                    // adyacente en lugar del token, y no sirve para
                    // identificar que credencial revocar.
                    "SECRET".equals(categoryOf(checkId))
                            ? Redaction.maskSecret(matchedText(extra))
                            : Redaction.truncateCode(text(extra, "lines")),
                    null, null, null,
                    // El simbolo del fingerprint es la regla mas la ruta, sin
                    // la linea: mover el codigo no debe generar un hallazgo
                    // nuevo.
                    checkId));
        }
        return findings;
    }

    /**
     * Las reglas de configuracion e infraestructura de Semgrep no son
     * vulnerabilidades de codigo. Separarlas importa porque el Risk Engine las
     * pondera distinto y el dashboard las agrupa aparte.
     */
    private static String categoryOf(String checkId) {
        if (checkId == null) {
            return "VULNERABILITY";
        }
        String id = checkId.toLowerCase();
        if (id.contains("dockerfile") || id.contains("terraform")
                || id.contains("kubernetes") || id.contains("docker-compose")) {
            return "MISCONFIGURATION";
        }
        if (id.contains("secret") || id.contains("hardcoded")) {
            return "SECRET";
        }
        return "VULNERABILITY";
    }

    private static String shortTitle(String message, String checkId) {
        if (message == null || message.isBlank()) {
            return checkId != null ? checkId : "Hallazgo de analisis estatico";
        }
        String oneLine = message.strip().replaceAll("\\s+", " ");
        int dot = oneLine.indexOf(". ");
        if (dot > 20 && dot < 150) {
            return oneLine.substring(0, dot);
        }
        return oneLine.length() > 150 ? oneLine.substring(0, 147) + "..." : oneLine;
    }

    private static String firstCwe(JsonNode cwe) {
        if (cwe.isArray() && !cwe.isEmpty()) {
            return extractCweId(cwe.get(0).asText());
        }
        if (cwe.isTextual()) {
            return extractCweId(cwe.asText());
        }
        return null;
    }

    /** Semgrep escribe "CWE-89: SQL Injection"; el esquema quiere solo el id. */
    private static String extractCweId(String raw) {
        if (raw == null) {
            return null;
        }
        int colon = raw.indexOf(':');
        String id = colon > 0 ? raw.substring(0, colon) : raw;
        return id.strip().startsWith("CWE-") ? id.strip() : null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull() || !value.isTextual()) {
            return null;
        }
        String s = value.asText();
        return s.isBlank() ? null : s;
    }

    private static Integer intOrNull(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isInt() && value.asInt() > 0 ? value.asInt() : null;
    }

    private String extractErrors(java.nio.file.Path stdout) {
        try {
            if (java.nio.file.Files.size(stdout) == 0) {
                return null;
            }
            return errorSummary(mapper.readTree(stdout.toFile()));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Resume el array "errors" en una linea legible. Se queda con los dos
     * primeros: cuando las reglas no cargan, el resto suele ser el mismo
     * problema repetido.
     */
    private static String errorSummary(JsonNode root) {
        JsonNode errors = root.path("errors");
        if (!errors.isArray() || errors.isEmpty()) {
            return "sin detalle";
        }
        StringBuilder sb = new StringBuilder();
        int limite = Math.min(2, errors.size());
        for (int i = 0; i < limite; i++) {
            JsonNode e = errors.get(i);
            if (i > 0) {
                sb.append(" | ");
            }
            String msg = e.path("long_msg").asText(e.path("message").asText(
                    e.path("short_msg").asText("error")));
            sb.append(e.path("type").asText("error")).append(": ").append(msg);
            JsonNode span = e.path("spans").path(0).path("file");
            if (span.isTextual()) {
                sb.append(" [").append(span.asText()).append("]");
            }
        }
        if (errors.size() > limite) {
            sb.append(" (+").append(errors.size() - limite).append(" mas)");
        }
        String out = sb.toString();
        return out.length() > 800 ? out.substring(0, 800) : out;
    }

    /**
     * Texto que hizo coincidir la regla.
     *
     * Semgrep lo expone en extra.metavars, donde cada metavariable trae su
     * abstract_content. Se prefiere la mas larga: en las reglas de secretos
     * suele ser el propio token. Si no hay metavars, se cae a la linea, que
     * es mejor que nada aunque sea menos preciso.
     */
    private static String matchedText(JsonNode extra) {
        JsonNode metavars = extra.path("metavars");
        String mejor = null;
        if (metavars.isObject()) {
            var nombres = metavars.fieldNames();
            while (nombres.hasNext()) {
                String contenido = text(metavars.path(nombres.next()), "abstract_content");
                if (contenido != null && (mejor == null || contenido.length() > mejor.length())) {
                    mejor = contenido;
                }
            }
        }
        return mejor != null ? mejor : text(extra, "lines");
    }
}
