package com.devguard.worker.analyzer.process;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class ProcessRunner {

    private static final Logger log = LoggerFactory.getLogger(ProcessRunner.class);
    private static final int STDERR_LIMIT = 4000;

    public Mono<ProcessResult> run(List<String> command, Path workingDir,
                                   Map<String, String> extraEnv, Duration timeout) {
        return Mono.fromCallable(() -> execute(command, workingDir, extraEnv, timeout))
                // Ejecutar un proceso es bloqueante por naturaleza: fuera del
                // event loop.
                .subscribeOn(Schedulers.boundedElastic());
    }


    private ProcessResult execute(List<String> command, Path workingDir,
                                  Map<String, String> extraEnv, Duration timeout) throws IOException, InterruptedException {
        Path stdout = Files.createTempFile("devguard-out-", ".json");
        Path stderr = Files.createTempFile("devguard-err-", ".json");

        ProcessBuilder pb = new ProcessBuilder(command)
                .redirectOutput(stdout.toFile())
                .redirectError(stderr.toFile());

        if (workingDir != null) {
            pb.directory(workingDir.toFile());
        }

        if (extraEnv != null) {
            pb.environment().putAll(extraEnv);
        }

        log.debug("Ejecutando: {}", String.join(" ", command));
        long inicio = System.currentTimeMillis();

        Process process = pb.start();
        boolean terminoSolo = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);

        if (!terminoSolo) {
            // destroyForcibly solo sobre el padre dejaria vivos a los hijos.
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            process.waitFor(10, TimeUnit.SECONDS);
            Files.deleteIfExists(stdout);
            Files.deleteIfExists(stderr);
            throw new ProcessTimeoutException(
                    command.get(0) + " excedio el limite de " + timeout.toSeconds() + "s"
            );

        }
        String errorOutput = readLimited(stderr);
        Files.deleteIfExists(stderr);

        return new ProcessResult(
                process.exitValue(),
                stdout,
                errorOutput,
                System.currentTimeMillis() - inicio);

    }

    private static String readLimited(Path path) {
        try {
            byte[] bytes = Files.readAllBytes(path);
            String text = new String(bytes, StandardCharsets.UTF_8);
            return text.length() > STDERR_LIMIT ? text.substring(0, STDERR_LIMIT) : text;
        } catch (IOException e) {
            return "";
        }
    }

    public record ProcessResult(int exitCode, Path stdoutFile, String stderr, long durationMs) {
        public void cleanup() {
            try {
                Files.deleteIfExists(stdoutFile);
            } catch (IOException ignored) {

            }
        }
    }

    public static class ProcessTimeoutException extends RuntimeException {
        public ProcessTimeoutException(String message) {
            super(message);
        }
    }

}
