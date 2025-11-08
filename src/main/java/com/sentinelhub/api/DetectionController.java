package com.sentinelhub.api;

import com.sentinelhub.common.model.SecurityEvent;
import com.sentinelhub.common.model.ThreatAlert;
import com.sentinelhub.detection.DetectionEngine;
import com.sentinelhub.detection.DetectionRule;
import com.sentinelhub.detection.ThreatHuntingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/detection")
public class DetectionController {

    private final DetectionEngine detectionEngine;
    private final ThreatHuntingService huntingService;

    public DetectionController(DetectionEngine detectionEngine,
                               ThreatHuntingService huntingService) {
        this.detectionEngine = detectionEngine;
        this.huntingService = huntingService;
    }

    @PostMapping("/rules")
    public ResponseEntity<DetectionRule> createRule(@RequestBody DetectionRule rule) {
        detectionEngine.registerRule(rule);
        return ResponseEntity.ok(rule);
    }

    @GetMapping("/rules")
    public ResponseEntity<List<DetectionRule>> listRules() {
        return ResponseEntity.ok(detectionEngine.listRules());
    }

    @PostMapping("/rules/{ruleId}/enable")
    public ResponseEntity<Map<String, String>> enableRule(@PathVariable String ruleId) {
        detectionEngine.enableRule(ruleId);
        return ResponseEntity.ok(Map.of("status", "enabled"));
    }

    @PostMapping("/rules/{ruleId}/disable")
    public ResponseEntity<Map<String, String>> disableRule(@PathVariable String ruleId) {
        detectionEngine.disableRule(ruleId);
        return ResponseEntity.ok(Map.of("status", "disabled"));
    }

    @PostMapping("/events")
    public ResponseEntity<List<ThreatAlert>> ingestEvent(@RequestBody SecurityEvent event) {
        List<ThreatAlert> alerts = detectionEngine.evaluateEvent(event);
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/alerts")
    public ResponseEntity<List<ThreatAlert>> getActiveAlerts() {
        return ResponseEntity.ok(detectionEngine.getActiveAlerts());
    }

    @GetMapping("/alerts/{alertId}")
    public ResponseEntity<ThreatAlert> getAlert(@PathVariable String alertId) {
        ThreatAlert alert = detectionEngine.getAlert(alertId);
        if (alert == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(alert);
    }

    @PostMapping("/alerts/{alertId}/resolve")
    public ResponseEntity<Map<String, String>> resolveAlert(
            @PathVariable String alertId,
            @RequestBody Map<String, String> body) {
        detectionEngine.resolveAlert(alertId, body.get("resolution"));
        return ResponseEntity.ok(Map.of("status", "resolved"));
    }

    @PostMapping("/hunt")
    public ResponseEntity<ThreatHuntingService.HuntResult> executeHunt(
            @RequestBody ThreatHuntingService.HuntRequest request) {
        ThreatHuntingService.HuntResult result = huntingService.executeHunt(request);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/hunt/history")
    public ResponseEntity<List<ThreatHuntingService.HuntResult>> getHuntHistory(
            @RequestParam(defaultValue = "10") int limit) {
        return ResponseEntity.ok(huntingService.getHuntHistory(limit));
    }
}
