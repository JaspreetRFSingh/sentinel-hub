package com.sentinelhub.detection;

import com.sentinelhub.common.model.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ThreatHuntingService {

    private static final Logger logger = LoggerFactory.getLogger(ThreatHuntingService.class);

    private final Map<String, HuntQuery> savedQueries = new ConcurrentHashMap<>();
    private final List<HuntResult> huntHistory = Collections.synchronizedList(new ArrayList<>());

    public void saveQuery(HuntQuery query) {
        savedQueries.put(query.getQueryId(), query);
        logger.info("Saved hunt query: {}", query.getName());
    }

    public HuntResult executeHunt(HuntRequest request) {
        logger.info("Executing threat hunt: {}", request.getName());

        Instant startTime = Instant.now();
        List<SecurityEvent> matchingEvents = new ArrayList<>();

        for (String indicator : request.getIndicators()) {
            List<SecurityEvent> results = searchByIndicator(indicator, request.getTimeRange());
            matchingEvents.addAll(results);
        }

        Duration executionTime = Duration.between(startTime, Instant.now());

        HuntResult result = new HuntResult(
            UUID.randomUUID().toString(),
            request.getName(),
            request.getIndicators(),
            matchingEvents,
            matchingEvents.size(),
            executionTime.toMillis(),
            Instant.now(),
            request.getAnalyst()
        );

        huntHistory.add(result);
        logger.info("Threat hunt completed: {} findings in {}ms", 
            result.findingCount(), result.executionTimeMs());

        return result;
    }

    private List<SecurityEvent> searchByIndicator(String indicator, Duration timeRange) {
        List<SecurityEvent> results = new ArrayList<>();
        
        logger.debug("Searching for indicator: {}", indicator);
        
        if (isValidIp(indicator)) {
            results.addAll(searchByIp(indicator));
        } else if (isValidDomain(indicator)) {
            results.addAll(searchByDomain(indicator));
        } else if (isValidHash(indicator)) {
            results.addAll(searchByHash(indicator));
        } else {
            results.addAll(searchByUser(indicator));
        }

        return results;
    }

    private List<SecurityEvent> searchByIp(String ip) {
        logger.debug("IP-based search: {}", ip);
        return List.of();
    }

    private List<SecurityEvent> searchByDomain(String domain) {
        logger.debug("Domain-based search: {}", domain);
        return List.of();
    }

    private List<SecurityEvent> searchByHash(String hash) {
        logger.debug("Hash-based search: {}", hash);
        return List.of();
    }

    private List<SecurityEvent> searchByUser(String user) {
        logger.debug("User-based search: {}", user);
        return List.of();
    }

    private boolean isValidIp(String indicator) {
        return indicator.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    }

    private boolean isValidDomain(String indicator) {
        return indicator.matches("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    }

    private boolean isValidHash(String indicator) {
        return indicator.matches("^[a-fA-F0-9]{32}$") || 
               indicator.matches("^[a-fA-F0-9]{40}$") || 
               indicator.matches("^[a-fA-F0-9]{64}$");
    }

    public List<HuntResult> getHuntHistory(int limit) {
        synchronized (huntHistory) {
            return huntHistory.stream()
                .skip(Math.max(0, huntHistory.size() - limit))
                .toList();
        }
    }

    public HuntResult getHuntResult(String huntId) {
        return huntHistory.stream()
            .filter(h -> h.huntId().equals(huntId))
            .findFirst()
            .orElse(null);
    }

    public static class HuntQuery {
        private String queryId;
        private String name;
        private String description;
        private String query;
        private List<String> tags;

        public String getQueryId() { return queryId; }
        public void setQueryId(String queryId) { this.queryId = queryId; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getQuery() { return query; }
        public void setQuery(String query) { this.query = query; }
        public List<String> getTags() { return tags; }
        public void setTags(List<String> tags) { this.tags = tags; }
    }

    public static class HuntRequest {
        private String name;
        private List<String> indicators;
        private Duration timeRange;
        private String analyst;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public List<String> getIndicators() { return indicators; }
        public void setIndicators(List<String> indicators) { this.indicators = indicators; }
        public Duration getTimeRange() { return timeRange; }
        public void setTimeRange(Duration timeRange) { this.timeRange = timeRange; }
        public String getAnalyst() { return analyst; }
        public void setAnalyst(String analyst) { this.analyst = analyst; }
    }

    public record HuntResult(
        String huntId,
        String huntName,
        List<String> indicators,
        List<SecurityEvent> findings,
        int findingCount,
        long executionTimeMs,
        Instant executedAt,
        String analyst
    ) {}
}
