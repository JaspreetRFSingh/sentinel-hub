package com.sentinelhub.api;

import com.sentinelhub.common.model.Incident;
import com.sentinelhub.common.model.ThreatAlert;
import com.sentinelhub.incident.IncidentManagementService;
import com.sentinelhub.incident.IncidentResponsePlaybookService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/incidents")
public class IncidentController {

    private final IncidentManagementService incidentService;
    private final IncidentResponsePlaybookService playbookService;

    public IncidentController(IncidentManagementService incidentService,
                              IncidentResponsePlaybookService playbookService) {
        this.incidentService = incidentService;
        this.playbookService = playbookService;
    }

    @PostMapping
    public ResponseEntity<Incident> createIncident(
            @RequestBody IncidentManagementService.IncidentRequest request) {
        Incident incident = incidentService.createIncident(request);
        return ResponseEntity.ok(incident);
    }

    @PostMapping("/from-alert/{alertId}")
    public ResponseEntity<Incident> createFromAlert(@PathVariable String alertId) {
        ThreatAlert alert = new ThreatAlert(
            alertId, "rule-1", "Test Rule",
            ThreatAlert.AlertSeverity.MEDIUM, ThreatAlert.AlertStatus.NEW,
            List.of(), "Test", "Test", List.of(), List.of(),
            java.time.Instant.now(), java.time.Instant.now(), null
        );
        Incident incident = incidentService.createFromAlert(alert);
        return ResponseEntity.ok(incident);
    }

    @GetMapping
    public ResponseEntity<List<Incident>> listIncidents() {
        return ResponseEntity.ok(incidentService.listIncidents());
    }

    @GetMapping("/{incidentId}")
    public ResponseEntity<Incident> getIncident(@PathVariable String incidentId) {
        Incident incident = incidentService.getIncident(incidentId);
        if (incident == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(incident);
    }

    @PostMapping("/{incidentId}/status")
    public ResponseEntity<Map<String, String>> updateStatus(
            @PathVariable String incidentId,
            @RequestParam Incident.IncidentStatus status,
            @RequestParam String updatedBy) {
        incidentService.updateStatus(incidentId, status, updatedBy);
        return ResponseEntity.ok(Map.of("status", "updated"));
    }

    @PostMapping("/{incidentId}/assign")
    public ResponseEntity<Map<String, String>> assignIncident(
            @PathVariable String incidentId,
            @RequestParam String assignee,
            @RequestParam String assignedBy) {
        incidentService.assignIncident(incidentId, assignee, assignedBy);
        return ResponseEntity.ok(Map.of("status", "assigned"));
    }

    @PostMapping("/{incidentId}/escalate")
    public ResponseEntity<Map<String, String>> escalateIncident(
            @PathVariable String incidentId,
            @RequestParam String reason,
            @RequestParam String escalatedBy) {
        incidentService.escalateIncident(incidentId, reason, escalatedBy);
        return ResponseEntity.ok(Map.of("status", "escalated"));
    }

    @PostMapping("/{incidentId}/resolve")
    public ResponseEntity<Map<String, String>> resolveIncident(
            @PathVariable String incidentId,
            @RequestParam String rootCause,
            @RequestParam String resolvedBy) {
        incidentService.resolveIncident(incidentId, rootCause, resolvedBy);
        return ResponseEntity.ok(Map.of("status", "resolved"));
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<Incident>> getIncidentsByStatus(
            @PathVariable Incident.IncidentStatus status) {
        return ResponseEntity.ok(incidentService.getIncidentsByStatus(status));
    }

    @PostMapping("/playbooks/{playbookId}/execute")
    public ResponseEntity<IncidentResponsePlaybookService.PlaybookExecution> executePlaybook(
            @PathVariable String playbookId,
            @RequestParam String incidentId,
            @RequestParam String executor) {
        IncidentResponsePlaybookService.PlaybookExecution execution = 
            playbookService.executePlaybook(playbookId, incidentId, executor);
        return ResponseEntity.ok(execution);
    }

    @GetMapping("/playbooks")
    public ResponseEntity<List<IncidentResponsePlaybookService.Playbook>> listPlaybooks() {
        return ResponseEntity.ok(playbookService.listPlaybooks());
    }
}
