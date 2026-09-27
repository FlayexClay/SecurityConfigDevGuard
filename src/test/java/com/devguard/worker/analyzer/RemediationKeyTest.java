package com.devguard.worker.analyzer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * La clave de remediacion identifica la ACCION, no el hallazgo.
 *
 * Lo que estas pruebas protegen es la diferencia entre decirle al usuario que
 * tiene 36 problemas y decirle que tiene uno. Si la clave se vuelve demasiado
 * especifica, la agrupacion desaparece en silencio: nada falla, simplemente el
 * dashboard vuelve a mostrar 36 filas.
 */
@DisplayName("Clave de remediacion")
class RemediationKeyTest {

    @Test
    @DisplayName("varios CVE del mismo paquete comparten clave")
    void dependenciasDelMismoPaquete() {
        var cve1 = dependency("xstream", "1.4.5", "CVE-2013-7285");
        var cve2 = dependency("xstream", "1.4.5", "CVE-2021-39139");

        assertThat(RemediationKey.of("DEPENDENCY", cve1))
                .isEqualTo(RemediationKey.of("DEPENDENCY", cve2))
                .isEqualTo("dependency:xstream");
    }

    /**
     * La version instalada NO entra en la clave. Si entrara, un CVE nuevo
     * descubierto para la misma version del paquete crearia un grupo aparte, y
     * el usuario veria dos acciones cuando la unica accion es actualizar.
     */
    @Test
    @DisplayName("la clave no depende de la version instalada")
    void versionNoAfectaLaClave() {
        var vieja = dependency("jackson-databind", "2.13.0", "CVE-2022-42003");
        var nueva = dependency("jackson-databind", "2.14.1", "CVE-2022-42004");

        assertThat(RemediationKey.of("DEPENDENCY", vieja))
                .isEqualTo(RemediationKey.of("DEPENDENCY", nueva));
    }

    @Test
    @DisplayName("paquetes distintos no se mezclan")
    void paquetesDistintos() {
        assertThat(RemediationKey.of("DEPENDENCY", dependency("xstream", "1.0", "CVE-1")))
                .isNotEqualTo(
                        RemediationKey.of("DEPENDENCY", dependency("log4j-core", "1.0", "CVE-2")));
    }

    @Test
    @DisplayName("el nombre del paquete se normaliza a minusculas")
    void normalizaMayusculas() {
        assertThat(RemediationKey.of("DEPENDENCY", dependency("XStream", "1.0", "CVE-1")))
                .isEqualTo("dependency:xstream");
    }

    @Test
    @DisplayName("varios secretos en el mismo archivo comparten clave")
    void secretosDelMismoArchivo() {
        var uno = secret(".env", "aws-key", 3);
        var otro = secret(".env", "generic-password", 17);

        assertThat(RemediationKey.of("SECRET", uno))
                .isEqualTo(RemediationKey.of("SECRET", otro))
                .isEqualTo("secret:.env");
    }

    /**
     * Es la misma razon por la que el fingerprint no incluye la linea: mover
     * el codigo no debe generar un hallazgo nuevo, ni partir un grupo en dos.
     */
    @Test
    @DisplayName("la clave de codigo no depende de la linea")
    void lineaNoAfectaLaClave() {
        var arriba = code("java.sql-injection", "src/UserRepo.java", 40);
        var abajo = code("java.sql-injection", "src/UserRepo.java", 180);

        assertThat(RemediationKey.of("SAST", arriba))
                .isEqualTo(RemediationKey.of("SAST", abajo));
    }

    @Test
    @DisplayName("la misma regla en archivos distintos son acciones distintas")
    void mismaReglaArchivosDistintos() {
        assertThat(RemediationKey.of("SAST", code("xss", "a.js", 1)))
                .isNotEqualTo(RemediationKey.of("SAST", code("xss", "b.js", 1)));
    }

    @Test
    @DisplayName("sin datos para agrupar, el hallazgo es su propio grupo")
    void sinDatosDeAgrupacion() {
        var huerfano = new RawFinding("VULNERABILITY", "LOW", "Algo", null, null,
                null, null, null, null, null, null, null, null, null, null, null, null);

        String clave = RemediationKey.of("SAST", huerfano);

        assertThat(clave).startsWith("finding:");
    }

    /**
     * Se usa el fingerprint y no un aleatorio: con un identificador nuevo en
     * cada ejecucion, el mismo hallazgo crearia un grupo distinto en cada scan
     * y el historial no serviria para nada.
     */
    @Test
    @DisplayName("el grupo de un hallazgo sin agrupacion es estable entre scans")
    void grupoHuerfanoEstable() {
        var huerfano = new RawFinding("VULNERABILITY", "LOW", "Algo", null, null,
                null, null, null, null, null, null, null, null, null, null, null, null);

        assertThat(RemediationKey.of("SAST", huerfano))
                .isEqualTo(RemediationKey.of("SAST", huerfano));
    }

    // ------------------------------------------------------------ utilidades

    private static RawFinding dependency(String pkg, String version, String cve) {
        return new RawFinding("DEPENDENCY", "HIGH", cve, null, null, cve, null, cve,
                7.5, "pom.xml", null, null, null, pkg, version, "9.9.9", pkg);
    }

    private static RawFinding secret(String path, String ruleId, int line) {
        return new RawFinding("SECRET", "HIGH", "Credencial", null, null, ruleId,
                "CWE-798", null, null, path, line, line, "AKIA****", null, null, null, ruleId);
    }

    private static RawFinding code(String ruleId, String path, int line) {
        return new RawFinding("VULNERABILITY", "HIGH", "Problema", null, null, ruleId,
                "CWE-89", null, null, path, line, line, null, null, null, null, "metodo");
    }
}
