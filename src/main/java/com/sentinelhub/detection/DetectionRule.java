package com.sentinelhub.detection;

import java.time.Duration;
import java.util.List;
import java.util.Map;

public class DetectionRule {
    
    private String ruleId;
    private String name;
    private String description;
    private RuleType type;
    private RuleSeverity severity;
    private String query;
    private Duration evaluationWindow;
    private int threshold;
    private List<String> dataSource;
    private Map<String, Object> parameters;
    private boolean enabled;
    private List<String> tags;
    private String mitigation;

    public enum RuleType {
        SIGNATURE_BASED,
        ANOMALY_BASED,
        BEHAVIORAL,
        THREAT_INTEL,
        COMPLIANCE,
        CUSTOM
    }

    public enum RuleSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public RuleType getType() { return type; }
    public void setType(RuleType type) { this.type = type; }
    public RuleSeverity getSeverity() { return severity; }
    public void setSeverity(RuleSeverity severity) { this.severity = severity; }
    public String getQuery() { return query; }
    public void setQuery(String query) { this.query = query; }
    public Duration getEvaluationWindow() { return evaluationWindow; }
    public void setEvaluationWindow(Duration evaluationWindow) { this.evaluationWindow = evaluationWindow; }
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
    public List<String> getDataSource() { return dataSource; }
    public void setDataSource(List<String> dataSource) { this.dataSource = dataSource; }
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    public String getMitigation() { return mitigation; }
    public void setMitigation(String mitigation) { this.mitigation = mitigation; }
}
