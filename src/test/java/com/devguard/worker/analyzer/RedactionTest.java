package com.devguard.worker.analyzer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enmascarado de evidencia.
 *
 * Estas pruebas defienden algo que no se ve en ninguna pantalla: que la base
 * de DevGuard no se convierta en el mayor almacen de secretos filtrados de sus
 * clientes. Un escaner de secretos encuentra credenciales reales, y un unico
 * acceso a esa tabla sin enmascarar daria las credenciales de todos los
 * tenants a la vez.
 *
 * Es el tipo de fallo que no lanza excepciones ni rompe nada: simplemente el
 * secreto queda guardado entero y nadie se entera hasta que es tarde.
 */
@DisplayName("Enmascarado de evidencia")
class RedactionTest {

    @Test
    @DisplayName("un secreto conserva solo cuatro caracteres")
    void enmascaraSecreto() {
        String masked = Redaction.maskSecret("AKIAIOSFODNN7EXAMPLE");

        assertThat(masked).startsWith("AKIA");
        assertThat(masked).doesNotContain("IOSFODNN7EXAMPLE");
    }

    @Test
    @DisplayName("ninguna parte del secreto sobrevive mas alla del prefijo")
    void noFiltraElResto() {
        String secreto = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        String masked = Redaction.maskSecret(secreto);

        // El sufijo, que es la parte que identifica la credencial, no puede
        // aparecer en ningun caso.
        assertThat(masked).doesNotContain("uvwxyz");
        assertThat(masked).doesNotContain("1234567890");
        assertThat(masked.replace("*", "")).hasSize(4);
    }

    @Test
    @DisplayName("un secreto muy largo se recorta antes de enmascarar")
    void recortaSecretosLargos() {
        String masked = Redaction.maskSecret("A".repeat(5000));

        assertThat(masked).hasSizeLessThan(40);
    }

    @Test
    @DisplayName("un secreto de menos de cuatro caracteres se oculta por completo")
    void secretoMuyCorto() {
        assertThat(Redaction.maskSecret("ab")).isEqualTo("**");
        assertThat(Redaction.maskSecret("a")).isEqualTo("*");
    }

    @Test
    @DisplayName("nulo y vacio devuelven nulo, no una cadena enmascarada")
    void nuloYVacio() {
        assertThat(Redaction.maskSecret(null)).isNull();
        assertThat(Redaction.maskSecret("   ")).isNull();
    }

    /**
     * Los fragmentos de codigo NO se enmascaran: ahi la evidencia es
     * justamente lo que hace util el hallazgo para quien lo va a arreglar.
     */
    @Test
    @DisplayName("un fragmento de codigo se recorta pero se lee")
    void codigoNoSeEnmascara() {
        String code = Redaction.truncateCode("String q = \"SELECT * FROM u WHERE id=\" + id;");

        assertThat(code).contains("SELECT");
        assertThat(code).doesNotContain("*****");
    }

    @Test
    @DisplayName("el codigo largo se recorta con puntos suspensivos")
    void codigoLargo() {
        String code = Redaction.truncateCode("x".repeat(1000));

        assertThat(code).hasSizeLessThanOrEqualTo(310);
        assertThat(code).endsWith("...");
    }

    @Test
    @DisplayName("el codigo multilinea se aplana a una sola linea")
    void aplanaSaltosDeLinea() {
        String code = Redaction.truncateCode("if (x) {\n   doSomething();\n}");

        assertThat(code).doesNotContain("\n");
        assertThat(code).contains("doSomething");
    }
}
