package com.devguard.worker;

import org.flywaydb.core.Flyway;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Base de las pruebas de integracion del worker.
 *
 * Aqui hay un acoplamiento que conviene nombrar en lugar de disimular: el
 * esquema lo definen las migraciones de la API, asi que estas pruebas lo
 * aplican desde la carpeta del otro modulo por ruta de sistema de archivos.
 *
 * Es deliberado que el worker NO lleve Flyway en produccion: el esquema tiene
 * un solo dueño y dos componentes migrando la misma base es una carrera
 * esperando a ocurrir. Pero sus pruebas necesitan la estructura para verificar
 * el SQL de deduplicacion, que es justo la logica mas valiosa del modulo.
 *
 * La consecuencia practica: si alguien mueve la carpeta de migraciones, estas
 * pruebas fallan con un mensaje claro en lugar de compilar y no probar nada.
 */
@Testcontainers
@SpringBootTest(properties = "spring.main.web-application-type=none")
public abstract class AbstractWorkerIntegrationTest {

    private static final String MIGRATIONS = "../backend/src/main/resources/db/migration";

    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("devguard")
                    .withUsername("devguard")
                    .withPassword("devguard");

    static {
        POSTGRES.start();
        applySchema();
    }

    /**
     * El worker no tiene Flyway configurado, asi que se invoca a mano una sola
     * vez para toda la ejecucion.
     */
    private static void applySchema() {
        Path migrations = Path.of(MIGRATIONS).toAbsolutePath().normalize();
        if (!Files.isDirectory(migrations)) {
            throw new IllegalStateException(
                    "No se encontraron las migraciones en " + migrations
                            + ". Estas pruebas dependen del esquema que define el modulo backend; "
                            + "si la carpeta se movio, hay que actualizar la ruta.");
        }

        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("filesystem:" + migrations)
                .load()
                .migrate();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> String.format(
                "r2dbc:postgresql://%s:%d/%s",
                POSTGRES.getHost(),
                POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT),
                POSTGRES.getDatabaseName()));
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);

        // Analizadores simulados: estas pruebas verifican la persistencia, no
        // las herramientas externas. Levantar Trivy o Semgrep aqui añadiria
        // minutos y una fuente de fallos ajena a lo que se esta probando.
        registry.add("devguard.worker.simulated", () -> "true");
        registry.add("devguard.kafka.bootstrap-servers", () -> "localhost:1");
    }
}
