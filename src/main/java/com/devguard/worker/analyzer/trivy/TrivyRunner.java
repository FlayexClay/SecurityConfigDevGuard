package com.devguard.worker.analyzer.trivy;

import com.devguard.worker.analyzer.process.ProcessRunner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
@ConditionalOnProperty(name = "devguard.worker.simulated", havingValue = "false")
public class TrivyRunner {

    private static final Logger log = LoggerFactory.getLogger(TrivyRunner.class);

    private final ProcessRunner runner;
    private final ObjectMapper mapper;
    private final Duration timeout;
    private final String cacheDir;

    public TrivyRunner(ProcessRunner runner, ObjectMapper eventObjectMapper,
                       @Value("${devguard.worker.trivy.timeout-minutes:10}") long timeoutMinutes,
                       @Value("${devguard.worker.trivy.cache-dir:/var/devguard/trivy-cache}")
                       String cacheDir) {
        this.runner = runner;
        this.mapper = eventObjectMapper;
        this.timeout = Duration.ofMinutes(timeoutMinutes);
        this.cacheDir = cacheDir;
    }

    public Mono<JsonNode> scan(Path workspace, String scanners) {
        List<String> command = new ArrayList<>(List.of(
                "trivy", "filesystem",
                "--scanners", scanners,
                "--format", "json",
                "--quiet",
                // La cache se comparte entre scans: sin ella, Trivy
                // descargaria su base de vulnerabilidades en cada ejecucion.
                "--cache-dir", cacheDir,
                // Que falten datos no debe romper el scan: se distingue por
                // el codigo de salida, no por la ausencia de resultados.
                "--exit-code", "0",
                "."));

        return runner.run(command, workspace,
                        Map.of("TRIVY_NO_PROGRESS", "true"), timeout)
                .flatMap(result -> {
                    if (result.exitCode() != 0) {
                        result.cleanup();
                        return Mono.error(new IllegalStateException(
                                "trivy fallo (codigo " + result.exitCode() + "): "
                                        + result.stderr()));
                    }
                    try {
                        long size = java.nio.file.Files.size(result.stdoutFile());
                        if (size == 0) {
                            return Mono.error(new IllegalStateException(
                                    "trivy no produjo salida con --scanners "
                                            + scanners + ": " + result.stderr()));
                        }
                        // Se parsea desde el archivo, no desde un String: el
                        // JSON de un repositorio grande son decenas de MB.
                        JsonNode root = mapper.readTree(result.stdoutFile().toFile());
                        int resultados = root.path("Results").size();
                        if (resultados == 0) {
                            // Cero resultados no siempre significa "todo
                            // limpio". Con --scanners vuln suele significar que
                            // no habia manifiestos que analizar: trivy resuelve
                            // dependencias desde archivos de bloqueo, y un
                            // repositorio sin package-lock.json ni pom.xml no
                            // le da nada con lo que trabajar. Distinguir estos
                            // dos casos importa, porque presentar "sin
                            // vulnerabilidades" cuando en realidad no se
                            // analizo nada es enganar al usuario.
                            log.warn("trivy --scanners {} no encontro objetivos analizables; "
                                    + "revisar si el repositorio tiene manifiestos", scanners);
                        }
                        log.debug("trivy --scanners {} termino en {} ms con {} objetivos",
                                scanners, result.durationMs(), resultados);
                        return Mono.just(root);
                    } catch (Exception e) {
                        return Mono.error(new IllegalStateException(
                                "No se pudo leer la salida de trivy: " + e.getMessage(), e));
                    } finally {
                        result.cleanup();
                    }
                });
    }

}
