package com.devguard.worker.analyzer;

public class Severities {

    private Severities() {

    }

    /** Trivy: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN. */
    public static String fromTrivy(String severity) {
        if (severity == null) {
            return "INFO";
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> "CRITICAL";
            case "HIGH" -> "HIGH";
            case "MEDIUM" -> "MEDIUM";
            case "LOW" -> "LOW";
            default -> "INFO";
        };
    }

    /**
     * Semgrep: ERROR, WARNING, INFO.
     *
     * ERROR se traduce a HIGH y no a CRITICAL a proposito. En SAST, CRITICAL
     * deberia reservarse para lo que el Risk Engine confirme explotable; un
     * hallazgo estatico sin validar no merece el escalon mas alto, o el
     * dashboard acaba con veinte criticos que nadie revisa.
     */
    public static String fromSemgrep(String severity) {
        if (severity == null) {
            return "INFO";
        }
        return switch (severity.toUpperCase()) {
            case "ERROR" -> "HIGH";
            case "WARNING" -> "MEDIUM";
            case "INFO" -> "LOW";
            default -> "INFO";
        };
    }
}
