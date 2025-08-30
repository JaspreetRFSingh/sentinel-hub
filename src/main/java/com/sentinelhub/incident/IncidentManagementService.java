package com.sentinelhub.incident;

import com.sentinelhub.common.model.Incident;
import com.sentinelhub.common.model.ThreatAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class IncidentManagementService {

    private static final Logger logger = LoggerFactory.getLogger(IncidentManagementService.class);

    private final Map<String, Incident> incidents = new ConcurrentHashMap<>();
    private final Map<String, List<String>> alertToIncidentMap = new ConcurrentHashMap<>();

    public Incident createIncident(IncidentRequest request) {
        String incidentId = generateIncidentId();
        
        Incident incident = new Incident(
            incidentId,
            request.title(),
            request.severity(),
            Incident.IncidentStatus.OPEN,
            request.priority(),
            request.relatedAlertIds(),
            request.threatActors(),
            request.attackVector(),
            request.description(),
            null,
            request.affectedSystems(),
            new LinkedHashMap<>(),
            Instant.now(),
            Instant.now(),
            null,
            request.assignedTo(),
            request.tags()
        );

        incidents.put(incidentId, incident);

        for (String alertId : request.relatedAlertIds()) {
            alertToIncidentMap.computeIfAbsent(alertId, k -> new ArrayList<>()).add(incidentId);
        }

        addTimelineEntry(incidentId, "INCIDENT_CREATED", "Incident created by " + request.assignedTo());

        logger.info("Created incident: {} with severity {}", incidentId, request.severity());
        return incident;
    }

    public Incident getIncident(String incidentId) {
        return incidents.get(incidentId);
    }

    public List<Incident> listIncidents() {
        return new ArrayList<>(incidents.values());
    }

    public List<Incident> getIncidentsByStatus(Incident.IncidentStatus status) {
        return incidents.values().stream()
            .filter(i -> i.status() == status)
            .toList();
    }

    public void updateStatus(String incidentId, Incident.IncidentStatus status, String updatedBy) {
        Incident incident = incidents.get(incidentId);
        if (incident != null) {
            Incident updated = createCopy(incident, status, null);
            incidents.put(incidentId, updated);
            addTimelineEntry(incidentId, "STATUS_UPDATED", 
                "Status changed to " + status + " by " + updatedBy);
            logger.info("Updated incident {} status to {}", incidentId, status);
        }
    }

    public void assignIncident(String incidentId, String assignee, String assignedBy) {
        Incident incident = incidents.get(incidentId);
        if (incident != null) {
            Incident updated = createCopy(incident, null, assignee);
            incidents.put(incidentId, updated);
            addTimelineEntry(incidentId, "ASSIGNED", 
                "Incident assigned to " + assignee + " by " + assignedBy);
            logger.info("Assigned incident {} to {}", incidentId, assignee);
        }
    }

    public void escalateIncident(String incidentId, String reason, String escalatedBy) {
        Incident incident = incidents.get(incidentId);
        if (incident != null) {
            Incident.IncidentPriority newPriority = switch (incident.priority()) {
                case P2 -> Incident.IncidentPriority.P1;
                case P3 -> Incident.IncidentPriority.P2;
                case P4 -> Incident.IncidentPriority.P3;
                case P1 -> Incident.IncidentPriority.P1;
            };

            Incident updated = new Incident(
                incident.incidentId(),
                incident.title(),
                incident.severity(),
                Incident.IncidentStatus.ESCALATED,
                newPriority,
                incident.relatedAlertIds(),
                incident.threatActors(),
                incident.attackVector(),
                incident.description(),
                incident.rootCause(),
                incident.affectedSystems(),
                buildTimeline(incident, "ESCALATED", reason + " by " + escalatedBy),
                incident.createdAt(),
                Instant.now(),
                incident.resolvedAt(),
                incident.assignedTo(),
                incident.tags()
            );

            incidents.put(incidentId, updated);
            logger.info("Escalated incident {} to priority {}", incidentId, newPriority);
        }
    }

    public void resolveIncident(String incidentId, String rootCause, String resolvedBy) {
        Incident incident = incidents.get(incidentId);
        if (incident != null) {
            Incident updated = new Incident(
                incident.incidentId(),
                incident.title(),
                incident.severity(),
                Incident.IncidentStatus.RESOLVED,
                incident.priority(),
                incident.relatedAlertIds(),
                incident.threatActors(),
                incident.attackVector(),
                incident.description(),
                rootCause,
                incident.affectedSystems(),
                buildTimeline(incident, "RESOLVED", "Incident resolved by " + resolvedBy),
                incident.createdAt(),
                Instant.now(),
                Instant.now(),
                incident.assignedTo(),
                incident.tags()
            );

            incidents.put(incidentId, updated);
            logger.info("Resolved incident {}: {}", incidentId, rootCause);
        }
    }

    public Incident createFromAlert(ThreatAlert alert) {
        IncidentRequest request = new IncidentRequest(
            "Security Alert: " + alert.ruleName(),
            mapSeverity(alert.severity()),
            Incident.IncidentPriority.P2,
            List.of(alert.alertId()),
            List.of(),
            Incident.AttackVector.UNKNOWN,
            alert.description(),
            extractAffectedSystems(alert),
            alert.assignedTo(),
            List.of("AUTO_GENERATED", alert.ruleId())
        );

        return createIncident(request);
    }

    private Incident.IncidentSeverity mapSeverity(ThreatAlert.AlertSeverity severity) {
        return switch (severity) {
            case LOW -> Incident.IncidentSeverity.LOW;
            case MEDIUM -> Incident.IncidentSeverity.MEDIUM;
            case HIGH -> Incident.IncidentSeverity.HIGH;
            case CRITICAL -> Incident.IncidentSeverity.CRITICAL;
        };
    }

    private List<String> extractAffectedSystems(ThreatAlert alert) {
        return alert.affectedAssets() != null ? alert.affectedAssets() : List.of();
    }

    private String generateIncidentId() {
        return "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private Incident createCopy(Incident incident, Incident.IncidentStatus status, String assignee) {
        return new Incident(
            incident.incidentId(),
            incident.title(),
            incident.severity(),
            status != null ? status : incident.status(),
            incident.priority(),
            incident.relatedAlertIds(),
            incident.threatActors(),
            incident.attackVector(),
            incident.description(),
            incident.rootCause(),
            incident.affectedSystems(),
            incident.timeline(),
            incident.createdAt(),
            Instant.now(),
            incident.resolvedAt(),
            assignee != null ? assignee : incident.assignedTo(),
            incident.tags()
        );
    }

    private void addTimelineEntry(String incidentId, String event, String description) {
        Incident incident = incidents.get(incidentId);
        if (incident != null) {
            Map<String, String> newTimeline = new LinkedHashMap<>(incident.timeline());
            newTimeline.put(Instant.now().toString(), event + ": " + description);
            
            Incident updated = new Incident(
                incident.incidentId(),
                incident.title(),
                incident.severity(),
                incident.status(),
                incident.priority(),
                incident.relatedAlertIds(),
                incident.threatActors(),
                incident.attackVector(),
                incident.description(),
                incident.rootCause(),
                incident.affectedSystems(),
                newTimeline,
                incident.createdAt(),
                Instant.now(),
                incident.resolvedAt(),
                incident.assignedTo(),
                incident.tags()
            );
            
            incidents.put(incidentId, updated);
        }
    }

    private Map<String, String> buildTimeline(Incident incident, String event, String description) {
        Map<String, String> newTimeline = new LinkedHashMap<>(incident.timeline());
        newTimeline.put(Instant.now().toString(), event + ": " + description);
        return newTimeline;
    }

    public record IncidentRequest(
        String title,
        Incident.IncidentSeverity severity,
        Incident.IncidentPriority priority,
        List<String> relatedAlertIds,
        List<Incident.ThreatActor> threatActors,
        Incident.AttackVector attackVector,
        String description,
        List<String> affectedSystems,
        String assignedTo,
        List<String> tags
    ) {}
}
