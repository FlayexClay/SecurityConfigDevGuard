package com.devguard.worker.risk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas de la calibracion del Security Score.
 *
 * Son las mas importantes del proyecto y a la vez las que nadie escribe, por
 * un motivo concreto: un score mal calculado sigue siendo un numero. No lanza
 * excepciones, no deja rastro en el log y la interfaz lo pinta igual de bonito.
 * La primera version de la formula devolvia 0 para cualquier proyecto con mas
 * de 300 puntos de riesgo, y eso solo se detecto midiendo a mano.
 *
 * Los rangos son intencionadamente amplios: un ajuste fino de los parametros
 * no debe romper las pruebas, pero una regresion que aplane la curva o sature
 * el score si.
 */
@DisplayName("Calibracion del Security Score")
class RiskEngineTest {

    private final RiskEngine engine = new RiskEngine();

    // ------------------------------------------------------------ escenarios

    @Test
    @DisplayName("un proyecto sin hallazgos saca 100")
    void proyectoLimpio() {
        var result = engine.calculate(List.of(), 0, 0);

        assertThat(result.score()).isEqualTo(100);
        assertThat(result.grade()).isEqualTo("A");
        assertThat(result.counts().total()).isZero();
    }

    @Test
    @DisplayName("un solo hallazgo bajo apenas mueve el score")
    void unHallazgoBajo() {
        var result = engine.calculate(findings(0, 0, 0, 1), 1, 0);

        assertThat(result.score()).isBetween(93, 100);
        assertThat(result.grade()).isIn("A", "B");
    }

    @Test
    @DisplayName("unos cuantos medios bajan el score sin hundirlo")
    void variosMedios() {
        var result = engine.calculate(findings(0, 0, 5, 10), 0, 0);

        assertThat(result.score()).isBetween(75, 93);
    }

    /**
     * El techo es una decision de producto, no del calculo: da igual lo bien
     * que este el resto, con una vulnerabilidad critica abierta el proyecto no
     * puede sacar sobresaliente. Un promedio que permitiera compensar seria
     * enganoso en seguridad.
     */
    @Test
    @DisplayName("un CRITICAL impone el techo de 55 aunque todo lo demas este limpio")
    void techoPorCritical() {
        var result = engine.calculate(findings(1, 0, 0, 0), 1, 0);

        assertThat(result.score()).isLessThanOrEqualTo(55);
        assertThat(result.breakdown().get("techo_aplicado").toString()).contains("CRITICAL");
    }

    @Test
    @DisplayName("un HIGH sin criticos impone el techo de 75")
    void techoPorHigh() {
        var result = engine.calculate(findings(0, 1, 0, 0), 1, 0);

        assertThat(result.score()).isLessThanOrEqualTo(75);
        assertThat(result.breakdown().get("techo_aplicado").toString()).contains("HIGH");
    }

    /**
     * Esta es la prueba que la primera version de la formula habria suspendido.
     * Con escala 8.5 y exponente 0.62, cualquier proyecto grande daba 0, y un
     * score que siempre da 0 no distingue nada: es tan inutil como uno que
     * siempre da 100.
     */
    @Test
    @DisplayName("un proyecto con cientos de hallazgos no se satura en 0")
    void noSeSaturaEnCero() {
        var result = engine.calculate(findings(2, 50, 200, 277), 0, 0);

        assertThat(result.score())
                .as("un proyecto muy vulnerable debe puntuar bajo pero distinguible de 0")
                .isBetween(1, 40);
    }

    @Test
    @DisplayName("mas hallazgos de la misma gravedad siempre bajan o igualan el score")
    void monotonia() {
        int pocos = engine.calculate(findings(0, 2, 5, 5), 0, 0).score();
        int muchos = engine.calculate(findings(0, 10, 40, 60), 0, 0).score();
        int muchisimos = engine.calculate(findings(0, 40, 150, 200), 0, 0).score();

        assertThat(pocos).isGreaterThanOrEqualTo(muchos);
        assertThat(muchos).isGreaterThanOrEqualTo(muchisimos);
    }

    @Test
    @DisplayName("un proyecto peor nunca puntua mejor que uno mejor")
    void ordenEntreEscenarios() {
        int limpio = engine.calculate(List.of(), 0, 0).score();
        int leve = engine.calculate(findings(0, 0, 3, 5), 0, 0).score();
        int serio = engine.calculate(findings(0, 5, 20, 30), 0, 0).score();
        int grave = engine.calculate(findings(3, 20, 60, 100), 0, 0).score();

        assertThat(limpio).isGreaterThan(leve);
        assertThat(leve).isGreaterThan(serio);
        assertThat(serio).isGreaterThan(grave);
    }

    // --------------------------------------------------------------- estados

    @Test
    @DisplayName("los hallazgos resueltos o descartados no penalizan")
    void estadosInactivos() {
        List<FindingSnapshot> mezcla = new ArrayList<>(findings(1, 2, 0, 0));
        mezcla.add(snapshot("CRITICAL", "RESOLVED", null, "g-resuelto"));
        mezcla.add(snapshot("CRITICAL", "FALSE_POSITIVE", null, "g-falso"));
        mezcla.add(snapshot("CRITICAL", "ACCEPTED_RISK", null, "g-aceptado"));

        var soloActivos = engine.calculate(findings(1, 2, 0, 0), 0, 0);
        var conInactivos = engine.calculate(mezcla, 0, 0);

        assertThat(conInactivos.score()).isEqualTo(soloActivos.score());
        assertThat(conInactivos.counts().critical()).isEqualTo(1);
        assertThat(conInactivos.breakdown().get("hallazgos_excluidos")).isEqualTo(3);
    }

    @Test
    @DisplayName("REGRESSED cuenta como activo")
    void regresionPenaliza() {
        var conRegresion = engine.calculate(
                List.of(snapshot("CRITICAL", "REGRESSED", null, "g1")), 0, 0);

        assertThat(conRegresion.counts().critical()).isEqualTo(1);
        assertThat(conRegresion.score()).isLessThan(100);
    }

    // ------------------------------------------------------------ agrupacion

    /**
     * El caso real que motivo la agrupacion: 36 CVE de la misma biblioteca
     * ocupaban los diez primeros puestos del ranking y disparaban el riesgo de
     * dependencias. Se cierran actualizando una linea del pom.xml.
     */
    @Test
    @DisplayName("varios hallazgos de la misma accion cuentan como un grupo")
    void agrupacionPorRemediacion() {
        List<FindingSnapshot> mismoGrupo = new ArrayList<>();
        for (int i = 0; i < 36; i++) {
            mismoGrupo.add(snapshot(i == 0 ? "CRITICAL" : "HIGH", "OPEN", "pom.xml",
                    "dependency:xstream"));
        }

        List<FindingSnapshot> gruposDistintos = new ArrayList<>();
        for (int i = 0; i < 36; i++) {
            gruposDistintos.add(snapshot(i == 0 ? "CRITICAL" : "HIGH", "OPEN", "pom.xml",
                    "dependency:libreria-" + i));
        }

        var agrupado = engine.calculate(mismoGrupo, 0, 0);
        var disperso = engine.calculate(gruposDistintos, 0, 0);

        assertThat(agrupado.breakdown().get("grupos_de_remediacion")).isEqualTo(1);
        assertThat(disperso.breakdown().get("grupos_de_remediacion")).isEqualTo(36);

        assertThat(agrupado.score())
                .as("36 CVE de una biblioteca deben penalizar menos que 36 bibliotecas distintas")
                .isGreaterThan(disperso.score());
    }

    @Test
    @DisplayName("un grupo nunca pesa mas de 1.6 veces su peor miembro")
    void techoDeAcumulacionDelGrupo() {
        List<FindingSnapshot> uno = List.of(
                snapshot("HIGH", "OPEN", "pom.xml", "dependency:x"));

        List<FindingSnapshot> muchos = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            muchos.add(snapshot("HIGH", "OPEN", "pom.xml", "dependency:x"));
        }

        double riesgoUno = riesgo(engine.calculate(uno, 0, 0));
        double riesgoMuchos = riesgo(engine.calculate(muchos, 0, 0));

        assertThat(riesgoMuchos)
                .as("200 hallazgos de la misma accion no pueden pesar 200 veces mas")
                .isLessThanOrEqualTo(riesgoUno * 1.6 + 0.01);
    }

    // --------------------------------------------------------- contexto

    /**
     * Los tres falsos positivos de secretos que aparecieron al analizar
     * WebGoat estaban en material de leccion y en un test de Playwright. El
     * analizador acerto al detectar el patron, pero ninguno era una credencial
     * que hubiera que revocar.
     */
    @Test
    @DisplayName("un hallazgo en material de ejemplo pesa menos que uno en produccion")
    void contextoRebajaEjemplos() {
        var produccion = engine.calculate(List.of(
                snapshot("HIGH", "OPEN", "src/main/resources/application.yml", "g1")), 0, 0);
        var leccion = engine.calculate(List.of(
                snapshot("HIGH", "OPEN", "src/main/resources/lessons/jwt/JWT.html", "g1")), 0, 0);
        var test = engine.calculate(List.of(
                snapshot("HIGH", "OPEN", "src/it/java/webwolf/JwtUITest.java", "g1")), 0, 0);

        assertThat(riesgo(leccion)).isLessThan(riesgo(produccion));
        assertThat(riesgo(test)).isLessThan(riesgo(produccion));
    }

    @Test
    @DisplayName("el contexto rebaja pero nunca anula: un secreto en un test sigue contando")
    void contextoNoAnula() {
        var test = engine.calculate(List.of(
                snapshot("HIGH", "OPEN", "src/test/java/FooTest.java", "g1")), 0, 0);

        assertThat(riesgo(test))
                .as("bajarlo a cero seria decidir por el analista")
                .isGreaterThan(0.0);
        assertThat(test.score()).isLessThan(100);
    }

    // ---------------------------------------------------------- explicabilidad

    /**
     * El documento de diseño exige que el score sea explicable. Sin desglose,
     * el producto responde "48" y no puede justificarlo.
     */
    @Test
    @DisplayName("el desglose permite reconstruir el numero")
    void desgloseCompleto() {
        var result = engine.calculate(findings(1, 3, 7, 9), 4, 2);

        assertThat(result.breakdown())
                .containsKeys("base", "riesgo_ponderado", "penalizacion",
                        "score_antes_de_techo", "riesgo_por_categoria",
                        "hallazgos_activos", "grupos_de_remediacion", "formula");

        assertThat(result.breakdown().get("base")).isEqualTo(100);
        assertThat((Integer) result.breakdown().get("hallazgos_activos")).isEqualTo(20);
        assertThat(result.breakdown().get("formula").toString()).contains("techo");
    }

    @Test
    @DisplayName("las notas siguen la convencion de informes de seguridad")
    void notas() {
        assertThat(engine.calculate(List.of(), 0, 0).grade()).isEqualTo("A");
        // Una C ya es un aviso, no un aprobado holgado.
        assertThat(gradeOf(70)).isIn("C", "B");
        assertThat(gradeOf(20)).isIn("E", "F");
    }

    @Test
    @DisplayName("el recuento de nuevos y resueltos se traslada tal cual")
    void recuentos() {
        var result = engine.calculate(findings(0, 1, 2, 3), 5, 7);

        assertThat(result.newFindings()).isEqualTo(5);
        assertThat(result.resolvedFindings()).isEqualTo(7);
    }

    // ------------------------------------------------------------- utilidades

    private String gradeOf(int objetivo) {
        // Se busca un escenario que produzca aproximadamente ese score para
        // comprobar el mapeo de notas sin depender de los parametros exactos.
        for (int medios = 0; medios < 400; medios++) {
            var r = engine.calculate(findings(0, 0, medios, 0), 0, 0);
            if (r.score() <= objetivo) {
                return r.grade();
            }
        }
        return "F";
    }

    private static double riesgo(ScoreResult result) {
        return ((Number) result.breakdown().get("riesgo_ponderado")).doubleValue();
    }

    /** Cada hallazgo en su propio grupo, para medir el efecto de la severidad. */
    private static List<FindingSnapshot> findings(int critical, int high, int medium, int low) {
        List<FindingSnapshot> list = new ArrayList<>();
        int n = 0;
        for (int i = 0; i < critical; i++) list.add(snapshot("CRITICAL", "OPEN", null, "g" + n++));
        for (int i = 0; i < high; i++) list.add(snapshot("HIGH", "OPEN", null, "g" + n++));
        for (int i = 0; i < medium; i++) list.add(snapshot("MEDIUM", "OPEN", null, "g" + n++));
        for (int i = 0; i < low; i++) list.add(snapshot("LOW", "OPEN", null, "g" + n++));
        return list;
    }

    private static FindingSnapshot snapshot(String severity, String status,
                                            String filePath, String remediationKey) {
        return new FindingSnapshot(
                UUID.randomUUID(), "VULNERABILITY", severity, status,
                filePath, null, null, 0L, remediationKey);
    }
}
