package com.devguard.worker.risk;

import com.devguard.worker.event.DevGuardTopics;
import com.devguard.worker.event.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ScoreService {

    private static final Logger log = LoggerFactory.getLogger(ScoreService.class);

    private final ScoreRepository scores;
    private final RiskEngine engine;
    private final EventPublisher events;

    public ScoreService(ScoreRepository scores, RiskEngine engine, EventPublisher events) {
        this.scores = scores;
        this.engine = engine;
        this.events = events;
    }

    /**
     * Calcula y persiste el score al terminar un scan.
     *
     * Se ejecuta sobre TODOS los hallazgos activos del proyecto, no solo los de
     * este scan. Un scan parcial en el que fallo un analizador no debe borrar
     * del calculo los hallazgos que ese analizador encontro la vez anterior:
     * siguen abiertos mientras nadie demuestre lo contrario.
     */
    public Mono<Integer> calculateAndStore(UUID organizationId, UUID projectId,
                                           UUID scanId, OffsetDateTime scanStartedAt) {
        return scores.loadForScoring(projectId)
                .collectList()
                .flatMap(findings -> Mono.zip(
                                scores.countNewInScan(projectId, scanId),
                                scores.countResolvedInScan(projectId, scanStartedAt),
                                scores.previousScore(projectId).map(Optional_::of)
                                        .defaultIfEmpty(Optional_.empty()))
                        .flatMap(t -> persist(organizationId, projectId, scanId,
                                findings, t.getT1(), t.getT2(), t.getT3().value())));
    }

    private Mono<Integer> persist(UUID organizationId, UUID projectId, UUID scanId,
                                  List<FindingSnapshot> findings, int nuevos,
                                  int resueltos, Integer anterior) {

        ScoreResult result = engine.calculate(findings, nuevos, resueltos);

        Map<UUID, Integer> prioridades = prioridadesDesde(findings);

        return scores.save(organizationId, projectId, scanId, result, anterior)
                .then(scores.updatePriorities(prioridades))
                .then(publishIfChanged(organizationId, projectId, scanId, result, anterior))
                .thenReturn(result.score())
                .doOnSuccess(s -> log.info(
                        "Security Score de {}: {} ({}) | C{} H{} M{} L{} | anterior: {}",
                        projectId, result.score(), result.grade(),
                        result.counts().critical(), result.counts().high(),
                        result.counts().medium(), result.counts().low(),
                        anterior != null ? anterior : "sin historico"));
    }

    /**
     * Prioridad por GRUPO de remediacion, no por hallazgo.
     *
     * Este es el arreglo del problema que se vio en la primera medicion real:
     * los diez primeros puestos del ranking eran once CVE distintos de la
     * misma biblioteca. Tecnicamente estaban bien ordenados, pero como
     * respuesta a "que arreglo primero" eran inutiles: el usuario veia diez
     * entradas y creia tener diez problemas cuando tenia uno.
     *
     * Todos los miembros de un grupo reciben la MISMA prioridad, la del grupo.
     * Asi el dashboard puede ordenar por ese campo y obtener acciones
     * distintas en cada posicion.
     */
    private Map<UUID, Integer> prioridadesDesde(List<FindingSnapshot> findings) {
        Map<String, List<FindingSnapshot>> grupos = findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.remediationKey() != null
                                ? f.remediationKey() : f.id().toString()));

        List<Map.Entry<String, List<FindingSnapshot>>> ordenados = grupos.entrySet().stream()
                .sorted(Comparator.comparingDouble(
                                (Map.Entry<String, List<FindingSnapshot>> e) ->
                                        e.getValue().stream()
                                                .mapToDouble(RiskEngine::weightOf)
                                                .max().orElse(0))
                        .reversed())
                .toList();

        Map<UUID, Integer> prioridades = new HashMap<>();
        for (int i = 0; i < ordenados.size(); i++) {
            // Los veinte primeros grupos conservan su posicion exacta; son los
            // que el dashboard muestra como cola de trabajo. Mas alla, el
            // orden fino deja de importar.
            int prioridad = i < 20 ? i : 20;
            ordenados.get(i).getValue()
                    .forEach(f -> prioridades.put(f.id(), prioridad));
        }
        return prioridades;
    }

    /**
     * El evento solo se publica si el score cambio.
     *
     * Un SECURITY_SCORE_CHANGED en cada scan, incluso cuando nada se movio,
     * convertiria el topic en ruido y haria inutil cualquier alerta construida
     * encima.
     */
    private Mono<Void> publishIfChanged(UUID organizationId, UUID projectId, UUID scanId,
                                        ScoreResult result, Integer anterior) {
        if (anterior != null && anterior == result.score()) {
            return Mono.empty();
        }
        return events.publish(DevGuardTopics.SECURITY_SCORE_CHANGED,
                organizationId.toString(),
                new ScoreChangedEvent(projectId, scanId, result.score(), result.grade(),
                        anterior, result.counts().critical(), result.counts().high(),
                        result.newFindings(), result.resolvedFindings(),
                        OffsetDateTime.now()));
    }

    public record ScoreChangedEvent(
            UUID projectId, UUID scanId, int score, String grade, Integer previousScore,
            int criticalCount, int highCount, int newFindings, int resolvedFindings,
            OffsetDateTime occurredAt) {
    }

    /** Envoltorio minimo: Mono.zip no admite valores nulos. */
    private record Optional_(Integer value) {
        static Optional_ of(Integer v) {
            return new Optional_(v);
        }

        static Optional_ empty() {
            return new Optional_(null);
        }
    }
}
