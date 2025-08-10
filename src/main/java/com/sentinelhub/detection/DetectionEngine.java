package com.sentinelhub.detection;

import com.sentinelhub.common.model.SecurityEvent;
import com.sentinelhub.common.model.ThreatAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DetectionEngine {

    private static final Logger logger = LoggerFactory.getLogger(DetectionEngine.class);

    private final Map<String, DetectionRule> rules = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityEvent>> eventBuffer = new ConcurrentHashMap<>();
    private final Map<String, ThreatAlert> activeAlerts = new ConcurrentHashMap<>();

    public void registerRule(DetectionRule rule) {
        rules.put(rule.getRuleId(), rule);
        logger.info("Registered detection rule: {} ({})", rule.getName(), rule.getRuleId());
    }

    public void unregisterRule(String ruleId) {
        rules.remove(ruleId);
        logger.info("Unregistered detection rule: {}", ruleId);
    }

    public void enableRule(String ruleId) {
        DetectionRule rule = rules.get(ruleId);
        if (rule != null) {
            rule.setEnabled(true);
            logger.info("Enabled detection rule: {}", ruleId);
        }
    }

    public void disableRule(String ruleId) {
        DetectionRule rule = rules.get(ruleId);
        if (rule != null) {
            rule.setEnabled(false);
            logger.info("Disabled detection rule: {}", ruleId);
        }
    }

    public List<DetectionRule> listRules() {
        return new ArrayList<>(rules.values());
    }

    public List<ThreatAlert> evaluateEvent(SecurityEvent event) {
        List<ThreatAlert> triggeredAlerts = new ArrayList<>();

        bufferEvent(event);

        for (DetectionRule rule : rules.values()) {
            if (!rule.isEnabled()) {
                continue;
            }

            if (evaluateRule(rule, event)) {
                ThreatAlert alert = createAlert(rule, event);
                triggeredAlerts.add(alert);
                activeAlerts.put(alert.alertId(), alert);
                logger.warn("Detection rule triggered: {} - Alert ID: {}", 
                    rule.getName(), alert.alertId());
            }
        }

        return triggeredAlerts;
    }

    private boolean evaluateRule(DetectionRule rule, SecurityEvent event) {
        return switch (rule.getType()) {
            case SIGNATURE_BASED -> evaluateSignature(rule, event);
            case ANOMALY_BASED -> evaluateAnomaly(rule, event);
            case BEHAVIORAL -> evaluateBehavioral(rule, event);
            case THREAT_INTEL -> evaluateThreatIntel(rule, event);
            case COMPLIANCE -> evaluateCompliance(rule, event);
            case CUSTOM -> evaluateCustom(rule, event);
        };
    }

    private boolean evaluateSignature(DetectionRule rule, SecurityEvent event) {
        String query = rule.getQuery();
        
        if (query.contains("sourceIp") && event.sourceIp() != null) {
            if (query.contains(event.sourceIp())) {
                return true;
            }
        }
        
        if (query.contains("userId") && event.userId() != null) {
            if (query.contains(event.userId())) {
                return true;
            }
        }

        if (query.contains("type") && event.type() != null) {
            if (query.contains(event.type().name())) {
                return true;
            }
        }

        return false;
    }

    private boolean evaluateAnomaly(DetectionRule rule, SecurityEvent event) {
        List<SecurityEvent> buffer = eventBuffer.getOrDefault(event.userId(), List.of());
        
        if (buffer.size() < rule.getThreshold()) {
            return false;
        }

        long failedAttempts = buffer.stream()
            .filter(e -> e.properties().getOrDefault("success", true).equals(false))
            .count();

        return failedAttempts >= rule.getThreshold();
    }

    private boolean evaluateBehavioral(DetectionRule rule, SecurityEvent event) {
        List<SecurityEvent> buffer = eventBuffer.getOrDefault(
            event.hostname() != null ? event.hostname() : event.userId(), List.of());

        Map<String, Long> eventTypeCounts = buffer.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                e -> e.type().name(),
                java.util.stream.Collectors.counting()
            ));

        for (Map.Entry<String, Long> entry : eventTypeCounts.entrySet()) {
            if (entry.getValue() >= rule.getThreshold()) {
                logger.debug("Behavioral anomaly detected: {} events of type {}", 
                    entry.getValue(), entry.getKey());
                return true;
            }
        }

        return false;
    }

    private boolean evaluateThreatIntel(DetectionRule rule, SecurityEvent event) {
        Object indicators = rule.getParameters().get("threatIndicators");
        if (indicators instanceof List<?> indicatorList) {
            if (event.sourceIp() != null && indicatorList.contains(event.sourceIp())) {
                return true;
            }
            if (event.hostname() != null && indicatorList.contains(event.hostname())) {
                return true;
            }
        }
        return false;
    }

    private boolean evaluateCompliance(DetectionRule rule, SecurityEvent event) {
        Object requiredFields = rule.getParameters().get("requiredFields");
        if (requiredFields instanceof List<?> fields) {
            for (Object field : fields) {
                if (event.properties().get(field.toString()) == null) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean evaluateCustom(DetectionRule rule, SecurityEvent event) {
        logger.debug("Evaluating custom rule: {}", rule.getName());
        return false;
    }

    private void bufferEvent(SecurityEvent event) {
        String key = event.userId() != null ? event.userId() : 
                    (event.hostname() != null ? event.hostname() : "default");
        
        eventBuffer.computeIfAbsent(key, k -> new ArrayList<>()).add(event);
        
        List<SecurityEvent> buffer = eventBuffer.get(key);
        if (buffer.size() > 1000) {
            buffer.subList(0, buffer.size() - 1000).clear();
        }
    }

    private ThreatAlert createAlert(DetectionRule rule, SecurityEvent event) {
        String alertId = UUID.randomUUID().toString();
        
        return new ThreatAlert(
            alertId,
            rule.getRuleId(),
            rule.getName(),
            mapSeverity(rule.getSeverity()),
            ThreatAlert.AlertStatus.NEW,
            List.of(event),
            rule.getDescription(),
            rule.getMitigation(),
            extractAffectedAssets(event),
            extractThreatIndicators(event),
            Instant.now(),
            Instant.now(),
            null
        );
    }

    private ThreatAlert.AlertSeverity mapSeverity(DetectionRule.RuleSeverity severity) {
        return switch (severity) {
            case LOW -> ThreatAlert.AlertSeverity.LOW;
            case MEDIUM -> ThreatAlert.AlertSeverity.MEDIUM;
            case HIGH -> ThreatAlert.AlertSeverity.HIGH;
            case CRITICAL -> ThreatAlert.AlertSeverity.CRITICAL;
        };
    }

    private List<String> extractAffectedAssets(SecurityEvent event) {
        List<String> assets = new ArrayList<>();
        if (event.hostname() != null) {
            assets.add(event.hostname());
        }
        if (event.sourceIp() != null) {
            assets.add(event.sourceIp());
        }
        return assets;
    }

    private List<String> extractThreatIndicators(SecurityEvent event) {
        List<String> indicators = new ArrayList<>();
        if (event.sourceIp() != null) {
            indicators.add(event.sourceIp());
        }
        return indicators;
    }

    public ThreatAlert getAlert(String alertId) {
        return activeAlerts.get(alertId);
    }

    public List<ThreatAlert> getActiveAlerts() {
        return new ArrayList<>(activeAlerts.values());
    }

    public void resolveAlert(String alertId, String resolution) {
        ThreatAlert alert = activeAlerts.get(alertId);
        if (alert != null) {
            activeAlerts.put(alertId, new ThreatAlert(
                alert.alertId(),
                alert.ruleId(),
                alert.ruleName(),
                alert.severity(),
                ThreatAlert.AlertStatus.RESOLVED,
                alert.correlatedEvents(),
                alert.description(),
                resolution,
                alert.affectedAssets(),
                alert.threatIndicators(),
                alert.createdAt(),
                Instant.now(),
                alert.assignedTo()
            ));
            logger.info("Resolved alert: {}", alertId);
        }
    }
}
