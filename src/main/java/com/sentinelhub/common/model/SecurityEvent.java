package com.sentinelhub.common.model;

import java.time.Instant;
import java.util.Map;

public record SecurityEvent(
    String eventId,
    EventType type,
    String source,
    String sourceIp,
    String destinationIp,
    String userId,
    String hostname,
    Severity severity,
    Map<String, Object> properties,
    Instant timestamp,
    String rawLog
) {
    public enum EventType {
        AUTHENTICATION,
        AUTHORIZATION,
        NETWORK_TRAFFIC,
        FILE_ACCESS,
        PROCESS_EXECUTION,
        REGISTRY_MODIFICATION,
        DNS_QUERY,
        EMAIL,
        MALWARE_DETECTED,
        VULNERABILITY_SCAN,
        CUSTOM
    }

    public enum Severity {
        INFORMATIONAL,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
}
