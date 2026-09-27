package com.devguard.worker.analyzer.semgrep;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

public final class LanguageDetector {

    private static final Logger log = LoggerFactory.getLogger(LanguageDetector.class);

    /** Tope de archivos recorridos: la deteccion no debe convertirse en el cuello de botella. */
    private static final int MAX_FILES_VISITED = 50_000;

    /** Directorios que no aportan lenguaje y solo suman tiempo. */
    private static final Set<String> SKIP_DIRS = Set.of(
            ".git", "node_modules", "target", "build", "dist", "out",
            "vendor", ".venv", "venv", "__pycache__", ".gradle", ".idea",
            ".mvn", "bin", "obj");

    /**
     * Extension -> subdirectorios de semgrep-rules.
     *
     * Un lenguaje puede mapear a varios: TypeScript aprovecha tambien las
     * reglas de JavaScript, y los YAML de Kubernetes estan en su propio
     * directorio.
     */
    private static final Map<String, List<String>> EXTENSION_RULES = Map.ofEntries(
            Map.entry("java", List.of("java")),
            Map.entry("kt", List.of("kotlin", "java")),
            Map.entry("kts", List.of("kotlin")),
            Map.entry("scala", List.of("scala")),
            Map.entry("js", List.of("javascript")),
            Map.entry("jsx", List.of("javascript", "typescript")),
            Map.entry("mjs", List.of("javascript")),
            Map.entry("cjs", List.of("javascript")),
            Map.entry("ts", List.of("typescript", "javascript")),
            Map.entry("tsx", List.of("typescript", "javascript")),
            Map.entry("py", List.of("python")),
            Map.entry("go", List.of("go")),
            Map.entry("rb", List.of("ruby")),
            Map.entry("php", List.of("php")),
            Map.entry("cs", List.of("csharp")),
            Map.entry("c", List.of("c")),
            Map.entry("h", List.of("c")),
            Map.entry("cpp", List.of("cpp", "c")),
            Map.entry("cc", List.of("cpp", "c")),
            Map.entry("hpp", List.of("cpp")),
            Map.entry("rs", List.of("rust")),
            Map.entry("swift", List.of("swift")),
            Map.entry("ex", List.of("elixir")),
            Map.entry("exs", List.of("elixir")),
            Map.entry("clj", List.of("clojure")),
            Map.entry("sol", List.of("solidity")),
            Map.entry("sh", List.of("bash")),
            Map.entry("bash", List.of("bash")),
            Map.entry("tf", List.of("terraform")),
            Map.entry("html", List.of("html")),
            Map.entry("json", List.of("json")),
            Map.entry("yaml", List.of("yaml")),
            Map.entry("yml", List.of("yaml")));

    /** Archivos sin extension reconocibles por nombre. */
    private static final Map<String, List<String>> FILENAME_RULES = Map.of(
            "dockerfile", List.of("dockerfile"),
            "containerfile", List.of("dockerfile"));

    private LanguageDetector() {
    }

    /**
     * Devuelve los directorios de reglas a pasar como --config.
     *
     * Si no detecta nada utilizable, devuelve la raiz completa: es preferible
     * un scan lento a un scan que no analiza nada.
     */
    public static List<Path> detectConfigs(Path workspace, Path rulesRoot) {
        Map<String, Integer> conteo = contarExtensiones(workspace);

        Set<String> directorios = new LinkedHashSet<>();
        conteo.forEach((ext, n) -> {
            List<String> reglas = EXTENSION_RULES.get(ext);
            if (reglas != null) {
                directorios.addAll(reglas);
            }
        });

        // "generic" tiene reglas independientes del lenguaje (secretos en
        // configuracion, patrones peligrosos en texto). Siempre vale la pena.
        directorios.add("generic");

        List<Path> configs = directorios.stream()
                .map(rulesRoot::resolve)
                // Comprobar que existe: los nombres de los directorios de
                // semgrep-rules pueden cambiar entre versiones, y pasar una
                // ruta inexistente hace fallar el scan completo con codigo 7.
                .filter(Files::isDirectory)
                .toList();

        if (configs.isEmpty()) {
            log.warn("No se detectaron lenguajes conocidos; se usaran todas las reglas");
            return List.of(rulesRoot);
        }

        log.info("Lenguajes detectados: {} -> {} conjuntos de reglas",
                resumen(conteo), configs.size());
        return configs;
    }

    private static Map<String, Integer> contarExtensiones(Path workspace) {
        Map<String, Integer> conteo = new HashMap<>();
        if (workspace == null) {
            return conteo;
        }
        final int[] visitados = {0};

        try {
            Files.walkFileTree(workspace, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String nombre = dir.getFileName() != null
                            ? dir.getFileName().toString().toLowerCase(Locale.ROOT)
                            : "";
                    return SKIP_DIRS.contains(nombre)
                            ? FileVisitResult.SKIP_SUBTREE
                            : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (++visitados[0] > MAX_FILES_VISITED) {
                        return FileVisitResult.TERMINATE;
                    }
                    String nombre = file.getFileName().toString().toLowerCase(Locale.ROOT);

                    FILENAME_RULES.keySet().stream()
                            .filter(nombre::startsWith)
                            .findFirst()
                            .ifPresent(clave -> conteo.merge(clave, 1, Integer::sum));

                    int punto = nombre.lastIndexOf('.');
                    if (punto > 0 && punto < nombre.length() - 1) {
                        conteo.merge(nombre.substring(punto + 1), 1, Integer::sum);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.warn("No se pudo recorrer {} para detectar lenguajes: {}",
                    workspace, e.getMessage());
        }
        return conteo;
    }

    /** Los cinco mas frecuentes, para el log. */
    private static String resumen(Map<String, Integer> conteo) {
        return conteo.entrySet().stream()
                .filter(e -> EXTENSION_RULES.containsKey(e.getKey())
                        || FILENAME_RULES.containsKey(e.getKey()))
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(5)
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + ", " + b)
                .orElse("ninguno");
    }
}
