package com.devguard.worker.config;

import com.devguard.worker.event.DevGuardTopics;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.kafka.receiver.ReceiverOptions;
import reactor.kafka.sender.KafkaSender;
import reactor.kafka.sender.SenderOptions;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class KafkaConfig {
    
    private final String bootstrapServers;
    private final String consumerGroup;
    private final int maxConcurrentScans;

    public KafkaConfig(
            @Value("${devguard.kafka.bootstrap-servers}") String bootstrapServers,
            @Value("${devguard.kafka.consumer-group}") String consumerGroup,
            @Value("${devguard.worker.max-concurrent-scans}") int maxConcurrentScans) {
        this.bootstrapServers = bootstrapServers;
        this.consumerGroup = consumerGroup;
        this.maxConcurrentScans = maxConcurrentScans;
    }

    @Bean
    public ReceiverOptions<String, String> receiverOptions() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, maxConcurrentScans);
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 900_000);

        return ReceiverOptions.<String, String> create(props)
                .subscription(List.of(DevGuardTopics.SCAN_REQUESTED));
    }

    @Bean
    public KafkaSender<String, String> kafkaSender() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        props.put(ProducerConfig.CLIENT_ID_CONFIG, "devguard-security-worker");
        return KafkaSender.create(SenderOptions.create(props));
    }

    @Bean
    public ObjectMapper eventObjectMapper() {
        return new ObjectMapper().findAndRegisterModules();
    }

}
