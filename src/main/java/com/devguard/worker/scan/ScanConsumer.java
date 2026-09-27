package com.devguard.worker.scan;

import com.devguard.worker.event.DevGuardTopics;
import com.devguard.worker.event.EventPublisher;
import com.devguard.worker.event.ScanRequestedEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.kafka.receiver.KafkaReceiver;
import reactor.kafka.receiver.ReceiverOptions;
import reactor.kafka.receiver.ReceiverRecord;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
public class ScanConsumer {

    private static final Logger log = LoggerFactory.getLogger(ScanConsumer.class);

    private final ReceiverOptions<String, String> receiverOptions;
    private final ScanProcessor processor;
    private final EventPublisher events;
    private final ObjectMapper mapper;
    private final int concurrency;

    private Disposable subscription;

    public ScanConsumer(ReceiverOptions<String, String> receiverOptions,
                        ScanProcessor processor,
                        EventPublisher events,
                        ObjectMapper eventObjectMapper,
                        @Value("${devguard.worker.max-concurrent-scans}") int concurrency) {
        this.receiverOptions = receiverOptions;
        this.processor = processor;
        this.events = events;
        this.mapper = eventObjectMapper;
        this.concurrency = concurrency;
    }

    @PostConstruct
    public void start() {
        subscription = KafkaReceiver.create(receiverOptions)
                .receive()
                // flatMap con concurrencia limitada: es lo que impide que el
                // worker acepte mas scans de los que su memoria aguanta.
                .flatMap(this::handle, concurrency)
                // Si la cadena entera muere (broker caido, por ejemplo), se
                // reintenta con espera creciente en lugar de dejar el worker
                // vivo pero sordo.
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(5))
                        .maxBackoff(Duration.ofMinutes(2))
                        .doBeforeRetry(s -> log.warn(
                                "Reconectando al consumidor de Kafka tras un fallo: {}",
                                s.failure().getMessage())))
                .subscribe();

        log.info("Consumidor de {} iniciado con concurrencia {}",
                DevGuardTopics.SCAN_REQUESTED, concurrency);
    }

    private Mono<Void> handle(ReceiverRecord<String, String> record) {
        return Mono.fromCallable(() ->
                        mapper.readValue(record.value(), ScanRequestedEvent.class))
                .flatMap(processor::process)
                // Un mensaje ilegible no se puede reintentar: reintentarlo
                // daria un bucle infinito sobre el mismo offset. Va a la DLQ y
                // se confirma, para no bloquear la particion.
                .onErrorResume(error -> {
                    log.error("Mensaje descartado por error irrecuperable: {}",
                            error.getMessage());
                    return events.publish(DevGuardTopics.SCAN_DLQ,
                            record.key() != null ? record.key() : "sin-clave",
                            new DeadLetter(record.topic(), record.partition(),
                                    record.offset(), record.value(), error.toString()));
                })
                // La confirmacion va SIEMPRE al final y solo aqui. Con
                // auto-commit, Kafka daria por procesado un scan que sigue
                // corriendo, y si el worker muriera a mitad nadie lo retomaria.
                .doFinally(signal -> record.receiverOffset().acknowledge());
    }

    @PreDestroy
    public void stop() {
        if (subscription != null && !subscription.isDisposed()) {
            subscription.dispose();
            log.info("Consumidor de scans detenido");
        }
    }

    private record DeadLetter(String topic, int partition, long offset,
                              String payload, String error) {
    }

}
