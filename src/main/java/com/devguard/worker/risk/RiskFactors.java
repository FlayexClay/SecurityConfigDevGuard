package com.devguard.worker.risk;

import java.util.Locale;
import java.util.Set;

/**
 * Ajustes de contexto sobre la severidad declarada por el analizador.
 * <p>
 * El documento de diseño pide priorizar por impacto y no por cantidad, y esto
 * es donde eso ocurre. Un analizador solo sabe lo que encontro; no sabe si el
 * archivo es codigo de produccion, una prueba o material de ejemplo.
 * <p>
 * Los tres falsos positivos de secretos que aparecieron al analizar WebGoat
 * (uno en un .html de una leccion, otro en un logs.txt y otro en un test de
 * Playwright) son exactamente el caso: el analizador acerto al detectar el
 * patron, pero ninguno es una credencial que haya que revocar.
 */
public final class RiskFactors {

    /** Rutas que casi nunca llegan a produccion. */
    private static final Set<String> TEST_MARKERS = Set.of(
            "/test/", "/tests/", "/spec/", "/specs/", "/it/",
            "test.", "tests.", "_test", ".test.", "spec.",
            "/fixtures/", "/mocks/", "/__mocks__/", "/testdata/");

    /** Material de ejemplo, documentacion y datos de demostracion. */
    private static final Set<String> SAMPLE_MARKERS = Set.of(
            "/docs/", "/doc/", "/examples/", "/example/", "/samples/",
            "/demo/", "readme", "changelog", ".md", ".html", ".txt",
            "/lessons/", "/tutorial/");

    /** Lo contrario: configuracion real, donde un secreto si importa. */
    private static final Set<String> PRODUCTION_CONFIG = Set.of(
            "application.yml", "application.yaml", "application.properties",
            ".env", "docker-compose", "settings.py", "config.json",
            "appsettings.json", "web.config");

    private RiskFactors() {
    }

    /**
     * Multiplicador de contexto por la ruta del archivo.
     *
     * Deliberadamente NO baja a cero: un secreto en un test sigue siendo un
     * secreto en el repositorio, y si es real hay que rotarlo igual. Bajarlo a
     * cero seria decidir por el analista, que es justo lo que no debe hacer un
     * motor automatico.
     */
    public static double contextWeight(String filePath, String category) {
        if (filePath == null || filePath.isBlank()) {
            return 1.0;
        }
        String path = filePath.toLowerCase(Locale.ROOT);

        if (matchesAny(path, PRODUCTION_CONFIG)) {
            // Un secreto en configuracion real pesa mas que la media.
            return "SECRET".equals(category) ? 1.2 : 1.0;
        }
        if (matchesAny(path, TEST_MARKERS)) {
            return 0.3;
        }
        if (matchesAny(path, SAMPLE_MARKERS)) {
            return 0.2;
        }
        return 1.0;
    }

    /**
     * Peso base por severidad.
     *
     * La progresion es deliberadamente no lineal. Con pesos lineales, veinte
     * hallazgos bajos igualarian a un critico, y el score diria que un
     * proyecto con mucho ruido menor esta tan mal como uno con una brecha
     * grave. La pregunta que el producto promete responder es "que arreglo
     * primero", y eso exige que lo critico domine.
     */
    public static double severityWeight(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 40.0;
            case "HIGH" -> 15.0;
            case "MEDIUM" -> 4.0;
            case "LOW" -> 1.0;
            default -> 0.2;
        };
    }

    /**
     * Penalizacion por antiguedad.
     *
     * Un hallazgo critico abierto desde hace meses dice algo peor que uno
     * detectado ayer: el primero indica que el equipo lo vio y no actuo. Se
     * limita a 1.5 para que el tiempo no acabe dominando sobre la gravedad.
     */
    public static double ageWeight(long ageDays, String severity) {
        if (ageDays < 30) {
            return 1.0;
        }
        boolean grave = "CRITICAL".equals(severity) || "HIGH".equals(severity);
        double incremento = grave ? 0.25 : 0.1;
        double meses = Math.min(ageDays / 30.0, 4);
        return Math.min(1.0 + (meses - 1) * incremento, 1.5);
    }

    /**
     * Hay parche disponible o no.
     * <p>
     * Una vulnerabilidad con version corregida publicada es responsabilidad
     * directa del equipo: solo hay que actualizar. Una sin parche no se puede
     * arreglar actualizando, asi que penalizarla igual castigaria por algo
     * fuera de su control.
     */
    public static double fixAvailabilityWeight(String category, String fixedVersion) {
        if (!"DEPENDENCY".equals(category)) {
            return 1.0;
        }
        return (fixedVersion != null && !fixedVersion.isBlank()) ? 1.15 : 0.85;
    }

    private static boolean matchesAny(String path, Set<String> markers) {
        return markers.stream().anyMatch(path::contains);
    }
}
