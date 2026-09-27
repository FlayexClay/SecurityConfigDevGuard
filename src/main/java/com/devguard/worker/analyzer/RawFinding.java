package com.devguard.worker.analyzer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public record RawFinding(
        String category,
        String severity,
        String title,
        String description,
        String recommendation,
        String ruleId,
        String cwe,
        String cve,
        Double cvssScore,
        String filePath,
        Integer lineStart,
        Integer lineEnd,
        String evidence,
        String packageName,
        String installedVersion,
        String fixedVersion,
        String symbol) {

    public String fingerprint(String analyzer) {
        String material = String.join("|",
                nz(analyzer), nz(ruleId), nz(filePath), nz(symbol), nz(packageName));
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
