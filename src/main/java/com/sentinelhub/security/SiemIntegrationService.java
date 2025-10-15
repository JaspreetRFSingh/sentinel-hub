package com.sentinelhub.security;

import com.sentinelhub.common.model.SecurityEvent;
import com.sentinelhub.config.SecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SiemIntegrationService {

    private static final Logger logger = LoggerFactory.getLogger(SiemIntegrationService.class);

    private final SecurityConfig config;
    private final Map<String, LogForwarder> forwarders = new ConcurrentHashMap<>();

    public SiemIntegrationService(SecurityConfig config) {
        this.config = config;
        initializeForwarders();
    }

    private void initializeForwarders() {
        if (config.getSiem().isEnabled()) {
            String integrationType = config.getSiem().getIntegrationType();
            
            LogForwarder forwarder = switch (integrationType.toLowerCase()) {
                case "splunk" -> new SplunkForwarder(
                    config.getSiem().getSplunk().getHecUrl(),
                    config.getSiem().getSplunk().getHecToken()
                );
                case "sentinel" -> new AzureSentinelForwarder();
                case "qradar" -> new QRadarForwarder();
                default -> new GenericForwarder();
            };
            
            forwarders.put(integrationType.toLowerCase(), forwarder);
            logger.info("Initialized SIEM forwarder: {}", integrationType);
        }
    }

    public void forwardEvent(SecurityEvent event) {
        for (LogForwarder forwarder : forwarders.values()) {
            try {
                forwarder.forward(event);
            } catch (Exception e) {
                logger.error("Failed to forward event to SIEM: {}", e.getMessage());
            }
        }
    }

    public void forwardBatch(List<SecurityEvent> events) {
        for (LogForwarder forwarder : forwarders.values()) {
            try {
                forwarder.forwardBatch(events);
            } catch (Exception e) {
                logger.error("Failed to forward batch to SIEM: {}", e.getMessage());
            }
        }
    }

    public boolean isEnabled() {
        return config.getSiem().isEnabled();
    }

    private interface LogForwarder {
        void forward(SecurityEvent event);
        void forwardBatch(List<SecurityEvent> events);
    }

    private static class SplunkForwarder implements LogForwarder {
        private final String hecUrl;
        private final String hecToken;

        public SplunkForwarder(String hecUrl, String hecToken) {
            this.hecUrl = hecUrl;
            this.hecToken = hecToken;
        }

        @Override
        public void forward(SecurityEvent event) {
            if (hecUrl != null && hecToken != null) {
                logger.debug("Forwarding to Splunk HEC: {}", event.eventId());
            }
        }

        @Override
        public void forwardBatch(List<SecurityEvent> events) {
            logger.debug("Forwarding batch of {} events to Splunk", events.size());
        }
    }

    private static class AzureSentinelForwarder implements LogForwarder {
        @Override
        public void forward(SecurityEvent event) {
            logger.debug("Forwarding to Azure Sentinel: {}", event.eventId());
        }

        @Override
        public void forwardBatch(List<SecurityEvent> events) {
            logger.debug("Forwarding batch of {} events to Azure Sentinel", events.size());
        }
    }

    private static class QRadarForwarder implements LogForwarder {
        @Override
        public void forward(SecurityEvent event) {
            logger.debug("Forwarding to QRadar: {}", event.eventId());
        }

        @Override
        public void forwardBatch(List<SecurityEvent> events) {
            logger.debug("Forwarding batch of {} events to QRadar", events.size());
        }
    }

    private static class GenericForwarder implements LogForwarder {
        @Override
        public void forward(SecurityEvent event) {
            logger.debug("Forwarding to generic SIEM: {}", event.eventId());
        }

        @Override
        public void forwardBatch(List<SecurityEvent> events) {
            logger.debug("Forwarding batch of {} events to generic SIEM", events.size());
        }
    }
}
