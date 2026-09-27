package com.devguard.worker.analyzer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Normalizacion de severidades entre herramientas.
 *
 * Sin un punto unico de traduccion, el Security Score sumaria escalas
 * distintas y la restriccion findings_severity_ck del esquema rechazaria los
 * INSERT. Lo primero es peor que lo segundo: un INSERT rechazado se ve en el
 * log, una escala mal traducida solo produce un numero equivocado.
 */
@DisplayName("Normalizacion de severidades")
class SeveritiesTest {

    private static final java.util.Set<String> VALIDAS =
            java.util.Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

    @ParameterizedTest
    @CsvSource({
            "CRITICAL, CRITICAL",
            "HIGH,     HIGH",
            "MEDIUM,   MEDIUM",
            "LOW,      LOW",
            "UNKNOWN,  INFO",
            "critical, CRITICAL",
            "high,     HIGH"
    })
    @DisplayName("las severidades de Trivy se traducen sin perder nada")
    void trivy(String entrada, String esperada) {
        assertThat(Severities.fromTrivy(entrada)).isEqualTo(esperada);
    }

    /**
     * ERROR se traduce a HIGH y no a CRITICAL a proposito. En SAST, el escalon
     * mas alto deberia reservarse para lo que se confirme explotable; si cada
     * hallazgo estatico fuera critico, el dashboard acabaria con veinte
     * criticos que nadie revisa y el techo del score dejaria de significar algo.
     */
    @ParameterizedTest
    @CsvSource({
            "ERROR,   HIGH",
            "WARNING, MEDIUM",
            "INFO,    LOW",
            "error,   HIGH"
    })
    @DisplayName("las severidades de Semgrep se traducen a la escala interna")
    void semgrep(String entrada, String esperada) {
        assertThat(Severities.fromSemgrep(entrada)).isEqualTo(esperada);
    }

    @Test
    @DisplayName("Semgrep nunca produce CRITICAL")
    void semgrepNoEscalaACritical() {
        assertThat(Severities.fromSemgrep("ERROR")).isNotEqualTo("CRITICAL");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "  ", "RARO", "9", "SEVERE"})
    @DisplayName("cualquier valor desconocido cae en una severidad valida")
    void valoresInesperados(String entrada) {
        assertThat(Severities.fromTrivy(entrada)).isIn(VALIDAS);
        assertThat(Severities.fromSemgrep(entrada)).isIn(VALIDAS);
    }
}
