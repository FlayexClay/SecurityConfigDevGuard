package com.devguard.worker.risk;

import java.util.List;
import java.util.Map;

public record ScoreResult(
        int score,
        String grade,
        Counts counts,
        int newFindings,
        int resolvedFindings,
        Map<String, Object> breakdown,
        List<TopRisk> topRisks) {

    public record Counts(int critical, int high, int medium, int low, int info) {
        public int total() {
            return critical + high + medium + low + info;
        }
    }

    public record TopRisk(String id, String title, String severity,
                          String category, double weight) {
    }
}
