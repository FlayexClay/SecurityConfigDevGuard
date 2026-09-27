package com.devguard.worker.analyzer;

public final class Redaction {

    private static final int VISIBLE_PREFIX = 4;
    private static final int MAX_LENGTH = 80;

    private Redaction() {
    }

    /**
     * Enmascara el fragmento coincidente.
     *
     * Ojo con lo que se le pasa: si recibe la LINEA en lugar del fragmento,
     * conserva los cuatro primeros caracteres de la linea y no del secreto. En
     * una prueba real eso produjo una evidencia que decia "requires login",
     * texto que ni era el token ni servia para identificarlo. No se filtro
     * nada, pero la evidencia quedo inutil para quien tiene que ir a
     * revocarla.
     */
    public static String maskSecret(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.strip();
        if (trimmed.length() > MAX_LENGTH) {
            trimmed = trimmed.substring(0, MAX_LENGTH);
        }
        if (trimmed.length() <= VISIBLE_PREFIX) {
            return "*".repeat(trimmed.length());
        }
        return trimmed.substring(0, VISIBLE_PREFIX)
                + "*".repeat(Math.min(trimmed.length() - VISIBLE_PREFIX, 20));
    }

    /**
     * Fragmentos de codigo que no son secretos: se recortan pero no se
     * enmascaran, porque la evidencia es justamente lo que hace util el
     * hallazgo para quien lo va a arreglar.
     */
    public static String truncateCode(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String oneLine = raw.strip().replaceAll("\\s+", " ");
        return oneLine.length() > 300 ? oneLine.substring(0, 300) + "..." : oneLine;
    }
}
