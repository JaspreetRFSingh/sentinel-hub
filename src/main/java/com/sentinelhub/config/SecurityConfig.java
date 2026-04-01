package com.sentinelhub.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.List;

@ConfigurationProperties(prefix = "sentinelhub")
public class SecurityConfig {
    
    private ElasticsearchConfig elasticsearch = new ElasticsearchConfig();
    private KafkaConfig kafka = new KafkaConfig();
    private SiemConfig siem = new SiemConfig();
    private EdrConfig edr = new EdrConfig();
    private DetectionConfig detection = new DetectionConfig();
    private IncidentConfig incident = new IncidentConfig();

    public ElasticsearchConfig getElasticsearch() { return elasticsearch; }
    public void setElasticsearch(ElasticsearchConfig elasticsearch) { this.elasticsearch = elasticsearch; }
    public KafkaConfig getKafka() { return kafka; }
    public void setKafka(KafkaConfig kafka) { this.kafka = kafka; }
    public SiemConfig getSiem() { return siem; }
    public void setSiem(SiemConfig siem) { this.siem = siem; }
    public EdrConfig getEdr() { return edr; }
    public void setEdr(EdrConfig edr) { this.edr = edr; }
    public DetectionConfig getDetection() { return detection; }
    public void setDetection(DetectionConfig detection) { this.detection = detection; }
    public IncidentConfig getIncident() { return incident; }
    public void setIncident(IncidentConfig incident) { this.incident = incident; }

    public static class ElasticsearchConfig {
        private boolean enabled;
        private String hosts;
        private String username;
        private String password;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getHosts() { return hosts; }
        public void setHosts(String hosts) { this.hosts = hosts; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class KafkaConfig {
        private String bootstrapServers;
        private String securityEventsTopic;
        private String alertTopic;

        public String getBootstrapServers() { return bootstrapServers; }
        public void setBootstrapServers(String bootstrapServers) { this.bootstrapServers = bootstrapServers; }
        public String getSecurityEventsTopic() { return securityEventsTopic; }
        public void setSecurityEventsTopic(String securityEventsTopic) { this.securityEventsTopic = securityEventsTopic; }
        public String getAlertTopic() { return alertTopic; }
        public void setAlertTopic(String alertTopic) { this.alertTopic = alertTopic; }
    }

    public static class SiemConfig {
        private boolean enabled;
        private String integrationType;
        private SplunkConfig splunk = new SplunkConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getIntegrationType() { return integrationType; }
        public void setIntegrationType(String integrationType) { this.integrationType = integrationType; }
        public SplunkConfig getSplunk() { return splunk; }
        public void setSplunk(SplunkConfig splunk) { this.splunk = splunk; }

        public static class SplunkConfig {
            private String hecUrl;
            private String hecToken;

            public String getHecUrl() { return hecUrl; }
            public void setHecUrl(String hecUrl) { this.hecUrl = hecUrl; }
            public String getHecToken() { return hecToken; }
            public void setHecToken(String hecToken) { this.hecToken = hecToken; }
        }
    }

    public static class EdrConfig {
        private boolean enabled;
        private String integrationType;
        private CrowdStrikeConfig crowdstrike = new CrowdStrikeConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getIntegrationType() { return integrationType; }
        public void setIntegrationType(String integrationType) { this.integrationType = integrationType; }
        public CrowdStrikeConfig getCrowdstrike() { return crowdstrike; }
        public void setCrowdstrike(CrowdStrikeConfig crowdstrike) { this.crowdstrike = crowdstrike; }

        public static class CrowdStrikeConfig {
            private String clientId;
            private String clientSecret;
            private String baseUrl;

            public String getClientId() { return clientId; }
            public void setClientId(String clientId) { this.clientId = clientId; }
            public String getClientSecret() { return clientSecret; }
            public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
            public String getBaseUrl() { return baseUrl; }
            public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        }
    }

    public static class DetectionConfig {
        private int rulesRefreshIntervalSeconds;
        private double alertThreshold;

        public int getRulesRefreshIntervalSeconds() { return rulesRefreshIntervalSeconds; }
        public void setRulesRefreshIntervalSeconds(int rulesRefreshIntervalSeconds) { this.rulesRefreshIntervalSeconds = rulesRefreshIntervalSeconds; }
        public double getAlertThreshold() { return alertThreshold; }
        public void setAlertThreshold(double alertThreshold) { this.alertThreshold = alertThreshold; }
    }

    public static class IncidentConfig {
        private boolean autoEscalationEnabled;
        private int escalationTimeoutMinutes;

        public boolean isAutoEscalationEnabled() { return autoEscalationEnabled; }
        public void setAutoEscalationEnabled(boolean autoEscalationEnabled) { this.autoEscalationEnabled = autoEscalationEnabled; }
        public int getEscalationTimeoutMinutes() { return escalationTimeoutMinutes; }
        public void setEscalationTimeoutMinutes(int escalationTimeoutMinutes) { this.escalationTimeoutMinutes = escalationTimeoutMinutes; }
    }
}
