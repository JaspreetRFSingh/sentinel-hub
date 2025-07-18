package com.sentinelhub.common.model;

import java.time.Instant;
import java.util.List;

public record ThreatAlert(
    String alertId,
    String ruleId,
    String ruleName,
    AlertSeverity severity,
    AlertStatus status,
    List<SecurityEvent> correlatedEvents,
    String description,
    String recommendation,
    List<String> affectedAssets,
    List<String> threatIndicators,
    Instant createdAt,
    Instant updatedAt,
    String assignedTo
) {
    public enum AlertSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum AlertStatus {
        NEW,
        IN_PROGRESS,
        ESCALATED,
        RESOLVED,
        FALSE_POSITIVE,
        SUPPRESSED
    }
}
