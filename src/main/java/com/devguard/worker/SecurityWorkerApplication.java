package com.devguard.worker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Worker de analisis de seguridad.
 *
 * Proceso aparte de la API, y no por doctrina de microservicios: los
 * analizadores reales (Semgrep, Trivy) piden mas de 1 GB en picos y no deben
 * poder tumbar la API. Se comunica por eventos, lo que ademas deja el camino
 * abierto a separarlo del todo mas adelante.
 */
@SpringBootApplication
public class SecurityWorkerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityWorkerApplication.class, args);
    }
}
