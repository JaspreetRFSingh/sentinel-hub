package com.sentinelhub.security;

import com.sentinelhub.config.SecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class EdrIntegrationService {

    private static final Logger logger = LoggerFactory.getLogger(EdrIntegrationService.class);

    private final SecurityConfig config;
    private final Map<String, EdrConnector> connectors = new ConcurrentHashMap<>();

    public EdrIntegrationService(SecurityConfig config) {
        this.config = config;
        initializeConnectors();
    }

    private void initializeConnectors() {
        if (config.getEdr().isEnabled()) {
            String integrationType = config.getEdr().getIntegrationType();
            
            EdrConnector connector = switch (integrationType.toLowerCase()) {
                case "crowdstrike" -> new CrowdStrikeConnector(
                    config.getEdr().getCrowdstrike().getClientId(),
                    config.getEdr().getCrowdstrike().getClientSecret(),
                    config.getEdr().getCrowdstrike().getBaseUrl()
                );
                case "sentinelone" -> new SentinelOneConnector();
                default -> new GenericEdrConnector();
            };
            
            connectors.put(integrationType.toLowerCase(), connector);
            logger.info("Initialized EDR connector: {}", integrationType);
        }
    }

    public void isolateHost(String hostId, String reason) {
        for (EdrConnector connector : connectors.values()) {
            try {
                connector.isolateHost(hostId, reason);
                logger.info("Isolated host: {} - Reason: {}", hostId, reason);
            } catch (Exception e) {
                logger.error("Failed to isolate host {}: {}", hostId, e.getMessage());
            }
        }
    }

    public void quarantineFile(String hostId, String filePath) {
        for (EdrConnector connector : connectors.values()) {
            try {
                connector.quarantineFile(hostId, filePath);
                logger.info("Quarantined file: {} on host: {}", filePath, hostId);
            } catch (Exception e) {
                logger.error("Failed to quarantine file: {}", e.getMessage());
            }
        }
    }

    public void killProcess(String hostId, String processId) {
        for (EdrConnector connector : connectors.values()) {
            try {
                connector.killProcess(hostId, processId);
                logger.info("Killed process: {} on host: {}", processId, hostId);
            } catch (Exception e) {
                logger.error("Failed to kill process: {}", e.getMessage());
            }
        }
    }

    public List<HostInfo> getHostInfo(String hostId) {
        for (EdrConnector connector : connectors.values()) {
            try {
                return connector.getHostInfo(hostId);
            } catch (Exception e) {
                logger.error("Failed to get host info: {}", e.getMessage());
            }
        }
        return List.of();
    }

    public List<Detection> getDetections(String hostId) {
        for (EdrConnector connector : connectors.values()) {
            try {
                return connector.getDetections(hostId);
            } catch (Exception e) {
                logger.error("Failed to get detections: {}", e.getMessage());
            }
        }
        return List.of();
    }

    public boolean isEnabled() {
        return config.getEdr().isEnabled();
    }

    private interface EdrConnector {
        void isolateHost(String hostId, String reason);
        void quarantineFile(String hostId, String filePath);
        void killProcess(String hostId, String processId);
        List<HostInfo> getHostInfo(String hostId);
        List<Detection> getDetections(String hostId);
    }

    private static class CrowdStrikeConnector implements EdrConnector {
        private final String clientId;
        private final String clientSecret;
        private final String baseUrl;

        public CrowdStrikeConnector(String clientId, String clientSecret, String baseUrl) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.baseUrl = baseUrl;
        }

        @Override
        public void isolateHost(String hostId, String reason) {
            logger.debug("CrowdStrike: Isolating host {}", hostId);
        }

        @Override
        public void quarantineFile(String hostId, String filePath) {
            logger.debug("CrowdStrike: Quarantining file {} on host {}", filePath, hostId);
        }

        @Override
        public void killProcess(String hostId, String processId) {
            logger.debug("CrowdStrike: Killing process {} on host {}", processId, hostId);
        }

        @Override
        public List<HostInfo> getHostInfo(String hostId) {
            logger.debug("CrowdStrike: Getting host info for {}", hostId);
            return List.of();
        }

        @Override
        public List<Detection> getDetections(String hostId) {
            logger.debug("CrowdStrike: Getting detections for {}", hostId);
            return List.of();
        }
    }

    private static class SentinelOneConnector implements EdrConnector {
        @Override
        public void isolateHost(String hostId, String reason) {
            logger.debug("SentinelOne: Isolating host {}", hostId);
        }

        @Override
        public void quarantineFile(String hostId, String filePath) {
            logger.debug("SentinelOne: Quarantining file {} on host {}", filePath, hostId);
        }

        @Override
        public void killProcess(String hostId, String processId) {
            logger.debug("SentinelOne: Killing process {} on host {}", processId, hostId);
        }

        @Override
        public List<HostInfo> getHostInfo(String hostId) {
            logger.debug("SentinelOne: Getting host info for {}", hostId);
            return List.of();
        }

        @Override
        public List<Detection> getDetections(String hostId) {
            logger.debug("SentinelOne: Getting detections for {}", hostId);
            return List.of();
        }
    }

    private static class GenericEdrConnector implements EdrConnector {
        @Override
        public void isolateHost(String hostId, String reason) {
            logger.debug("Generic EDR: Isolating host {}", hostId);
        }

        @Override
        public void quarantineFile(String hostId, String filePath) {
            logger.debug("Generic EDR: Quarantining file {} on host {}", filePath, hostId);
        }

        @Override
        public void killProcess(String hostId, String processId) {
            logger.debug("Generic EDR: Killing process {} on host {}", processId, hostId);
        }

        @Override
        public List<HostInfo> getHostInfo(String hostId) {
            logger.debug("Generic EDR: Getting host info for {}", hostId);
            return List.of();
        }

        @Override
        public List<Detection> getDetections(String hostId) {
            logger.debug("Generic EDR: Getting detections for {}", hostId);
            return List.of();
        }
    }

    public record HostInfo(
        String hostId,
        String hostname,
        String os,
        String osVersion,
        String ipAddress,
        String lastSeen
    ) {}

    public record Detection(
        String detectionId,
        String hostId,
        String threatName,
        String severity,
        String status,
        String timestamp
    ) {}
}
