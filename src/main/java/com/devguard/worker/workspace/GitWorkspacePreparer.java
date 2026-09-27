package com.devguard.worker.workspace;

import com.devguard.worker.analyzer.process.ProcessRunner;
import com.devguard.worker.scan.ScanStateRepository.ScanRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Clonado del repositorio para analizarlo.
 *
 * Es el punto del sistema donde entra codigo de fuera, asi que concentra la
 * mayoria de las defensas.
 */
@Component
@ConditionalOnProperty(name = "devguard.worker.simulated", havingValue = "false")
public class GitWorkspacePreparer implements WorkspacePreparer {

    private static final Logger log = LoggerFactory.getLogger(GitWorkspacePreparer.class);
    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");
    private static final Duration CLONE_TIMEOUT = Duration.ofMinutes(5);

    private final ProcessRunner runner;
    private final Path workspaceRoot;
    private final long maxSizeBytes;

    public GitWorkspacePreparer(
            ProcessRunner runner,
            @Value("${devguard.worker.workspace}") String workspaceRoot,
            @Value("${devguard.worker.max-repo-size-mb:500}") long maxSizeMb) {
        this.runner = runner;
        this.workspaceRoot = Path.of(workspaceRoot);
        this.maxSizeBytes = maxSizeMb * 1024 * 1024;
    }

    @Override
    public Mono<ScanWorkspace> prepare(ScanRecord record) {
        // Segunda validacion del esquema, aunque la API ya lo comprobo al dar
        // de alta el repositorio. Aqui solo https: ssh exigiria gestionar
        // claves, y file:// o git:// convertirian al worker en un cliente de
        // peticiones arbitrarias dentro de la red interna.
        validateUrl(record.cloneUrl());

        Path target = workspaceRoot.resolve(record.scanId().toString());

        return Mono.fromCallable(() -> {
                    Files.createDirectories(target);
                    return target;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(dir -> clone(record, dir))
                .flatMap(dir -> checkSize(dir)
                        .flatMap(size -> resolveCommit(dir)
                                .map(sha -> new ScanWorkspace(dir, sha, size))))
                // Si algo falla a mitad del clonado, el directorio parcial no
                // debe quedarse ocupando disco.
                .onErrorResume(e -> deleteRecursively(target)
                        .then(Mono.error(e)));
    }

    private Mono<Path> clone(ScanRecord record, Path target) {
        List<String> command = List.of(
                "git",
                // Sin hooks: un repositorio no debe poder ejecutar nada en el
                // worker durante el checkout.
                "-c", "core.hooksPath=/dev/null",
                // Sin ayudantes de credenciales: si la URL pide autenticacion,
                // debe fallar en lugar de quedarse esperando o reutilizar
                // credenciales de otro sitio.
                "-c", "credential.helper=",
                "clone",
                // Solo el ultimo commit de una rama, sin etiquetas. Reduce el
                // clonado de un repositorio con años de historia a unos pocos
                // megabytes.
                "--depth", "1",
                "--single-branch",
                "--no-tags",
                "--branch", record.branch(),
                record.cloneUrl(),
                target.toString());

        Map<String, String> env = Map.of(
                // Nunca pedir credenciales por consola: sin esto, un
                // repositorio privado dejaria el proceso colgado hasta el
                // timeout.
                "GIT_TERMINAL_PROMPT", "0",
                "GIT_ASKPASS", "/bin/true",
                "GIT_CONFIG_NOSYSTEM", "1");

        return runner.run(command, null, env, CLONE_TIMEOUT)
                .flatMap(result -> {
                    result.cleanup();
                    if (result.exitCode() != 0) {
                        return Mono.error(new CloneException(
                                "git clone fallo (codigo " + result.exitCode() + "): "
                                        + firstLine(result.stderr())));
                    }
                    log.info("Repositorio clonado en {} ms", result.durationMs());
                    return Mono.just(target);
                });
    }

    private Mono<String> resolveCommit(Path dir) {
        return runner.run(List.of("git", "rev-parse", "HEAD"), dir, null,
                        Duration.ofSeconds(30))
                .map(result -> {
                    try {
                        String sha = Files.readString(result.stdoutFile(),
                                StandardCharsets.UTF_8).trim();
                        result.cleanup();
                        return sha;
                    } catch (IOException e) {
                        result.cleanup();
                        return "";
                    }
                })
                .filter(sha -> !sha.isBlank())
                .defaultIfEmpty("");
    }

    /**
     * Un repositorio enorme llenaria el disco de la instancia y afectaria a
     * todos los tenants, no solo al que pidio el scan. Se comprueba despues
     * del clonado porque git no ofrece una forma fiable de saber el tamaño
     * antes.
     */
    private Mono<Long> checkSize(Path dir) {
        return Mono.fromCallable(() -> {
                    long size = directorySize(dir);
                    if (size > maxSizeBytes) {
                        throw new CloneException("El repositorio ocupa "
                                + (size / 1024 / 1024) + " MB y el limite es "
                                + (maxSizeBytes / 1024 / 1024) + " MB");
                    }
                    return size;
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Void> cleanup(ScanWorkspace workspace) {
        if (workspace == null || workspace.isEmpty()) {
            return Mono.empty();
        }
        return deleteRecursively(workspace.path())
                .doOnSuccess(v -> log.debug("Workspace {} liberado", workspace.path()));
    }

    private Mono<Void> deleteRecursively(Path dir) {
        return Mono.fromRunnable(() -> {
                    if (!Files.exists(dir)) {
                        return;
                    }
                    try (var paths = Files.walk(dir)) {
                        paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                            try {
                                Files.deleteIfExists(p);
                            } catch (IOException e) {
                                log.warn("No se pudo borrar {}: {}", p, e.getMessage());
                            }
                        });
                    } catch (IOException e) {
                        log.warn("No se pudo recorrer {}: {}", dir, e.getMessage());
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    private static long directorySize(Path dir) throws IOException {
        final long[] total = {0};
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                // No seguir enlaces simbolicos: un repositorio puede contener
                // uno que apunte fuera del workspace y falsearia la cuenta.
                if (attrs.isRegularFile()) {
                    total[0] += attrs.size();
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        return total[0];
    }

    private static void validateUrl(String cloneUrl) {
        if (cloneUrl == null || cloneUrl.isBlank()) {
            throw new CloneException("El repositorio no tiene URL de clonado");
        }
        URI uri;
        try {
            uri = URI.create(cloneUrl);
        } catch (IllegalArgumentException e) {
            throw new CloneException("URL de clonado invalida");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new CloneException("Solo se admite https para clonar; recibido: " + scheme);
        }
    }

    private static String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "sin detalle";
        }
        int nl = text.indexOf('\n');
        return nl > 0 ? text.substring(0, nl) : text;
    }

    public static class CloneException extends RuntimeException {
        public CloneException(String message) {
            super(message);
        }
    }
}
