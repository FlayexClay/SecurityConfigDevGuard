package com.devguard.worker.analyzer;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Flux;

import java.time.Duration;
import java.util.List;

@Configuration
@ConditionalOnProperty(name = "devguard.worker.simulated", havingValue = "true",
        matchIfMissing = true)
public class SimulatedAnalyzers {

    @Bean
    public Analyzer simulatedDependencyAnalyzer() {
        return new Analyzer() {
            @Override
            public String name() {
                return "DEPENDENCY";
            }

            @Override
            public String version() {
                return "simulated-1.0";
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return Flux.fromIterable(List.of(
                                new RawFinding("DEPENDENCY", "CRITICAL",
                                        "Ejecucion remota de codigo en libreria de logging",
                                        "La version instalada permite ejecucion remota mediante "
                                                + "sustitucion de variables en mensajes de log.",
                                        "Actualizar a 2.17.1 o superior.",
                                        "CVE-2021-44228", "CWE-502", "CVE-2021-44228", 10.0,
                                        "pom.xml", 42, 42, null,
                                        "log4j-core", "2.14.1", "2.17.1", "log4j-core"),
                                new RawFinding("DEPENDENCY", "HIGH",
                                        "Deserializacion insegura en libreria de serializacion",
                                        "Permite instanciar clases arbitrarias al deserializar.",
                                        "Actualizar a 2.15.0 o superior.",
                                        "CVE-2022-42003", "CWE-502", "CVE-2022-42003", 7.5,
                                        "pom.xml", 58, 58, null,
                                        "jackson-databind", "2.13.0", "2.15.0",
                                        "jackson-databind"),
                                new RawFinding("DEPENDENCY", "MEDIUM",
                                        "Denegacion de servicio por expresion regular",
                                        "Una entrada manipulada provoca retroceso exponencial.",
                                        "Actualizar a 1.21.0.",
                                        "CVE-2023-1111", "CWE-1333", "CVE-2023-1111", 5.3,
                                        "package.json", 15, 15, null,
                                        "semver", "1.20.0", "1.21.0", "semver")))
                        // Latencia simulada: sin ella el scan terminaria tan
                        // rapido que no se veria el estado RUNNING.
                        .delaySequence(Duration.ofSeconds(2));
            }
        };
    }

    @Bean
    public Analyzer simulatedSecretAnalyzer() {
        return new Analyzer() {
            @Override
            public String name() {
                return "SECRET";
            }

            @Override
            public String version() {
                return "simulated-1.0";
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return Flux.fromIterable(List.of(
                                new RawFinding("SECRET", "CRITICAL",
                                        "Clave de acceso de proveedor cloud en el repositorio",
                                        "Se detecto una credencial con formato de clave de acceso.",
                                        "Revocar la credencial y moverla a un gestor de secretos. "
                                                + "Rotar aunque el repositorio sea privado.",
                                        "aws-access-key", "CWE-798", null, 9.1,
                                        "src/main/resources/application-dev.yml", 12, 12,
                                        // Evidencia enmascarada: el secreto
                                        // completo nunca se persiste.
                                        "AKIA****************", null, null, null,
                                        "aws_access_key_id"),
                                new RawFinding("SECRET", "HIGH",
                                        "Contrasena de base de datos embebida",
                                        "Credencial en texto plano dentro del control de versiones.",
                                        "Sustituir por una variable de entorno.",
                                        "generic-password", "CWE-798", null, 7.2,
                                        "docker-compose.override.yml", 8, 8,
                                        "pass****", null, null, null, "POSTGRES_PASSWORD")))
                        .delaySequence(Duration.ofSeconds(1));
            }
        };
    }

    @Bean
    public Analyzer simulatedSastAnalyzer() {
        return new Analyzer() {
            @Override
            public String name() {
                return "SAST";
            }

            @Override
            public String version() {
                return "simulated-1.0";
            }

            @Override
            public Flux<RawFinding> analyze(ScanContext context) {
                return Flux.fromIterable(List.of(
                                new RawFinding("VULNERABILITY", "HIGH",
                                        "Concatenacion de entrada de usuario en consulta SQL",
                                        "La consulta se construye concatenando un parametro "
                                                + "recibido por HTTP.",
                                        "Usar consultas parametrizadas.",
                                        "java.sql-injection", "CWE-89", null, 8.2,
                                        "src/main/java/com/example/UserRepository.java",
                                        88, 91, null, null, null, null, "findByName"),
                                new RawFinding("VULNERABILITY", "MEDIUM",
                                        "Algoritmo de hash obsoleto",
                                        "Se utiliza MD5 para derivar una representacion de "
                                                + "contrasena.",
                                        "Sustituir por bcrypt, scrypt o Argon2.",
                                        "java.weak-hash", "CWE-327", null, 5.9,
                                        "src/main/java/com/example/PasswordUtil.java",
                                        23, 25, null, null, null, null, "hashPassword"),
                                new RawFinding("MISCONFIGURATION", "LOW",
                                        "Contenedor ejecutandose como root",
                                        "El Dockerfile no declara un usuario sin privilegios.",
                                        "Anadir una instruccion USER.",
                                        "dockerfile.root-user", "CWE-250", null, 3.1,
                                        "Dockerfile", 1, 1, null, null, null, null, "USER")))
                        .delaySequence(Duration.ofSeconds(2));
            }
        };
    }
}