package com.devguard.worker.risk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class RiskEngine {

    private static final Logger log = LoggerFactory.getLogger(RiskEngine.class);

    /**
     * Estados que cuentan: lo resuelto o descartado no penaliza.
     */
    private static final Set<String> ACTIVE_STATUSES =
            Set.of("OPEN", "CONFIRMED", "REGRESSED");

    /**
     * Cuanto puede descontar el riesgo acumulado, como maximo.
     */
    private static final double MAX_PENALTY = 100.0;

    /**
     * Aplana la curva. Los tres valores estan calibrados contra escenarios
     * concretos, no elegidos a ojo:
     * <p>
     * proyecto limpio                      -> 100
     * un hallazgo bajo                     ->  97
     * unos cuantos medios                  ->  86
     * un HIGH con acompanamiento           ->  75 (techo)
     * un CRITICAL                          ->  55 (techo)
     * proyecto descuidado (3C/20H/60M)     ->  40
     * aplicacion vulnerable de ejemplo     ->   9
     * <p>
     * Con la parametrizacion inicial (escala 8.5, exponente 0.62) todo lo que
     * pasara de unos 300 puntos de riesgo daba 0, y un score que siempre da 0
     * es tan inutil como uno que siempre da 100.
     */
    private static final double DAMPENING_EXPONENT = 0.45;

    /**
     * Escala el riesgo antes de aplanarlo.
     */
    private static final double RISK_SCALE = 40.0;

    /**
     * Convierte el riesgo aplanado en puntos de penalizacion.
     */
    private static final double PENALTY_MULTIPLIER = 16.0;

    /**
     * Techos por presencia de hallazgos graves.
     */
    private static final int CRITICAL_CEILING = 55;
    private static final int HIGH_CEILING = 75;

    public ScoreResult calculate(List<FindingSnapshot> findings, int newFindings,
                                 int resolvedFindings) {

        List<FindingSnapshot> activos = findings.stream()
                .filter(f -> ACTIVE_STATUSES.contains(f.status()))
                .toList();

        ScoreResult.Counts counts = count(activos);

        // El riesgo se acumula por GRUPO de remediacion, no por hallazgo.
        //
        // Once CVE de la misma biblioteca se cierran actualizando una linea
        // del pom.xml. Sumarlos por separado inflaba el riesgo de
        // dependencias a 489 sobre 968 en la medicion real, y hacia que el
        // score castigara once veces un problema que cuesta un arreglo.
        Map<String, List<FindingSnapshot>> grupos = activos.stream()
                .collect(Collectors.groupingBy(
                        f -> f.remediationKey() != null
                                ? f.remediationKey() : f.id().toString(),
                        LinkedHashMap::new, Collectors.toList()));

        double riesgoTotal = 0;
        Map<String, Double> porCategoria = new TreeMap<>();
        List<ScoreResult.TopRisk> ponderados = new ArrayList<>();

        for (Map.Entry<String, List<FindingSnapshot>> grupo : grupos.entrySet()) {
            double peso = groupWeight(grupo.getValue());
            FindingSnapshot representante = peorDe(grupo.getValue());

            riesgoTotal += peso;
            porCategoria.merge(representante.category(), peso, Double::sum);
            ponderados.add(new ScoreResult.TopRisk(
                    grupo.getKey(), null, representante.severity(),
                    representante.category(), peso));
        }

        // Aplanado: la penalizacion crece con el riesgo, pero cada vez mas
        // despacio. Un proyecto con 500 hallazgos medios no debe puntuar igual
        // que uno con 500 criticos, pero tampoco debe dar 0 solo por ser grande.
        double penalizacion = Math.min(
                MAX_PENALTY,
                Math.pow(riesgoTotal / RISK_SCALE, DAMPENING_EXPONENT) * PENALTY_MULTIPLIER);

        int score = (int) Math.round(Math.max(0, 100 - penalizacion));

        int scoreAntesDeTecho = score;
        if (counts.critical() > 0) {
            score = Math.min(score, CRITICAL_CEILING);
        } else if (counts.high() > 0) {
            score = Math.min(score, HIGH_CEILING);
        }

        Map<String, Object> breakdown = new LinkedHashMap<>();
        breakdown.put("base", 100);
        breakdown.put("riesgo_ponderado", redondear(riesgoTotal));
        breakdown.put("penalizacion", redondear(penalizacion));
        breakdown.put("score_antes_de_techo", scoreAntesDeTecho);
        breakdown.put("techo_aplicado", score < scoreAntesDeTecho
                ? (counts.critical() > 0 ? "CRITICAL:" + CRITICAL_CEILING
                : "HIGH:" + HIGH_CEILING)
                : null);
        breakdown.put("riesgo_por_categoria", redondearValores(porCategoria));
        breakdown.put("hallazgos_activos", activos.size());
        breakdown.put("grupos_de_remediacion", grupos.size());
        breakdown.put("hallazgos_excluidos", findings.size() - activos.size());
        breakdown.put("formula",
                "100 - min(100, (riesgo/" + RISK_SCALE + ")^" + DAMPENING_EXPONENT
                        + " * " + PENALTY_MULTIPLIER + "), con techo " + CRITICAL_CEILING
                        + " si hay CRITICAL y " + HIGH_CEILING + " si hay HIGH");

        List<ScoreResult.TopRisk> top = ponderados.stream()
                .sorted(Comparator.comparingDouble(ScoreResult.TopRisk::weight).reversed())
                .limit(10)
                .toList();

        log.debug("Score {} ({}): riesgo {} sobre {} hallazgos activos",
                score, grade(score), redondear(riesgoTotal), activos.size());

        return new ScoreResult(score, grade(score), counts, newFindings,
                resolvedFindings, breakdown, top);
    }

    /**
     * Riesgo de un grupo de remediacion.
     * <p>
     * Es el peso del peor miembro mas un incremento decreciente por cada uno
     * adicional. La idea: once CVE en una biblioteca son peores que uno
     * —hay mas superficie y mas probabilidad de que alguno sea explotable—
     * pero no once veces peores, porque el esfuerzo de arreglarlo es el mismo.
     * <p>
     * El incremento es logaritmico y se limita al 60% del peso base, asi que
     * un grupo nunca puede pesar mas que 1.6 veces su peor miembro.
     */
    private static double groupWeight(List<FindingSnapshot> miembros) {
        double maximo = miembros.stream().mapToDouble(RiskEngine::weightOf).max().orElse(0);
        if (miembros.size() == 1) {
            return maximo;
        }
        double acumulacion = Math.min(0.6, Math.log(miembros.size()) * 0.18);
        return maximo * (1 + acumulacion);
    }

    static double weightOf(FindingSnapshot f) {
        return RiskFactors.severityWeight(f.severity())
                * RiskFactors.contextWeight(f.filePath(), f.category())
                * RiskFactors.ageWeight(f.ageDays(), f.severity())
                * RiskFactors.fixAvailabilityWeight(f.category(), f.fixedVersion());
    }

    private static FindingSnapshot peorDe(List<FindingSnapshot> miembros) {
        return miembros.stream()
                .max(Comparator.comparingDouble(RiskEngine::weightOf))
                .orElse(miembros.get(0));
    }

    private static ScoreResult.Counts count(List<FindingSnapshot> activos) {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        for (FindingSnapshot f : activos) {
            switch (f.severity()) {
                case "CRITICAL" -> c++;
                case "HIGH" -> h++;
                case "MEDIUM" -> m++;
                case "LOW" -> l++;
                default -> i++;
            }
        }
        return new ScoreResult.Counts(c, h, m, l, i);
    }

    /**
     * Las letras siguen la convencion de los informes de seguridad, no la de
     * las notas escolares: una C aqui ya es un aviso, no un aprobado holgado.
     */
    private static String grade(int score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 65) return "C";
        if (score >= 50) return "D";
        if (score >= 30) return "E";
        return "F";
    }

    private static double redondear(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    private static Map<String, Double> redondearValores(Map<String, Double> m) {
        Map<String, Double> out = new TreeMap<>();
        m.forEach((k, v) -> out.put(k, redondear(v)));
        return out;
    }
}
