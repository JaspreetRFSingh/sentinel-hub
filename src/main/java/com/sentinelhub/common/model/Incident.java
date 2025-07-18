package com.sentinelhub.common.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record Incident(
    String incidentId,
    String title,
    IncidentSeverity severity,
    IncidentStatus status,
    IncidentPriority priority,
    List<String> relatedAlertIds,
    List<ThreatActor> threatActors,
    AttackVector attackVector,
    String description,
    String rootCause,
    List<String> affectedSystems,
    Map<String, String> timeline,
    Instant createdAt,
    Instant updatedAt,
    Instant resolvedAt,
    String assignedTo,
    List<String> tags
) {
    public enum IncidentSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum IncidentStatus {
        OPEN,
        INVESTIGATING,
        CONTAINED,
        REMEDIATING,
        RESOLVED,
        CLOSED
    }

    public enum IncidentPriority {
        P1,
        P2,
        P3,
        P4
    }

    public record ThreatActor(
        String name,
        String type,
        String motivation,
        String sophistication
    ) {}

    public enum AttackVector {
        PHISHING,
        MALWARE,
        RANSOMWARE,
        DDoS,
        INSIDER_THREAT,
        APT,
        VULNERABILITY_EXPLOIT,
        CREDENTIAL_THEFT,
        UNKNOWN
    }
}
