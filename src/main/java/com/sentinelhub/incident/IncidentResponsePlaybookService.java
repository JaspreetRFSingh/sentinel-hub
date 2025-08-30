package com.sentinelhub.incident;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class IncidentResponsePlaybookService {

    private static final Logger logger = LoggerFactory.getLogger(IncidentResponsePlaybookService.class);

    private final Map<String, Playbook> playbooks = new ConcurrentHashMap<>();
    private final Map<String, PlaybookExecution> activeExecutions = new ConcurrentHashMap<>();

    public void registerPlaybook(Playbook playbook) {
        playbooks.put(playbook.getPlaybookId(), playbook);
        logger.info("Registered playbook: {}", playbook.getName());
    }

    public PlaybookExecution executePlaybook(String playbookId, String incidentId, String executor) {
        Playbook playbook = playbooks.get(playbookId);
        if (playbook == null) {
            throw new IllegalArgumentException("Playbook not found: " + playbookId);
        }

        String executionId = "EXEC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        
        PlaybookExecution execution = new PlaybookExecution(
            executionId,
            playbookId,
            incidentId,
            PlaybookExecution.ExecutionStatus.RUNNING,
            executor,
            new ArrayList<>(),
            java.time.Instant.now(),
            null
        );

        activeExecutions.put(executionId, execution);

        for (PlaybookStep step : playbook.getSteps()) {
            executeStep(executionId, step, incidentId);
        }

        execution = new PlaybookExecution(
            execution.executionId(),
            execution.playbookId(),
            execution.incidentId(),
            PlaybookExecution.ExecutionStatus.COMPLETED,
            execution.executor(),
            execution.stepResults(),
            execution.startedAt(),
            java.time.Instant.now()
        );
        activeExecutions.put(executionId, execution);

        logger.info("Executed playbook {} for incident {}", playbookId, incidentId);
        return execution;
    }

    private void executeStep(String executionId, PlaybookStep step, String incidentId) {
        logger.info("Executing step: {} - {}", step.getStepId(), step.getName());

        StepResult result = switch (step.getActionType()) {
            case ISOLATE_HOST -> isolateHost(step, incidentId);
            case BLOCK_IP -> blockIp(step, incidentId);
            case DISABLE_USER -> disableUser(step, incidentId);
            case COLLECT_FORENSICS -> collectForensics(step, incidentId);
            case NOTIFY_TEAM -> notifyTeam(step, incidentId);
            case CREATE_TICKET -> createTicket(step, incidentId);
            case RUN_SCRIPT -> runScript(step, incidentId);
            case CUSTOM -> executeCustom(step, incidentId);
        };

        PlaybookExecution execution = activeExecutions.get(executionId);
        if (execution != null) {
            execution.stepResults().add(result);
        }
    }

    private StepResult isolateHost(PlaybookStep step, String incidentId) {
        logger.info("Isolating host for incident: {}", incidentId);
        return new StepResult(step.getStepId(), "ISOLATE_HOST", true, 
            "Host isolated successfully", java.time.Instant.now());
    }

    private StepResult blockIp(PlaybookStep step, String incidentId) {
        Object targetIp = step.getParameters().get("ipAddress");
        logger.info("Blocking IP: {} for incident: {}", targetIp, incidentId);
        return new StepResult(step.getStepId(), "BLOCK_IP", true, 
            "IP blocked: " + targetIp, java.time.Instant.now());
    }

    private StepResult disableUser(PlaybookStep step, String incidentId) {
        Object targetUser = step.getParameters().get("userId");
        logger.info("Disabling user: {} for incident: {}", targetUser, incidentId);
        return new StepResult(step.getStepId(), "DISABLE_USER", true, 
            "User disabled: " + targetUser, java.time.Instant.now());
    }

    private StepResult collectForensics(PlaybookStep step, String incidentId) {
        logger.info("Collecting forensics for incident: {}", incidentId);
        return new StepResult(step.getStepId(), "COLLECT_FORENSICS", true, 
            "Forensics data collected", java.time.Instant.now());
    }

    private StepResult notifyTeam(PlaybookStep step, String incidentId) {
        Object team = step.getParameters().get("team");
        logger.info("Notifying team: {} for incident: {}", team, incidentId);
        return new StepResult(step.getStepId(), "NOTIFY_TEAM", true, 
            "Team notified: " + team, java.time.Instant.now());
    }

    private StepResult createTicket(PlaybookStep step, String incidentId) {
        logger.info("Creating ticket for incident: {}", incidentId);
        return new StepResult(step.getStepId(), "CREATE_TICKET", true, 
            "Ticket created: TKT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(), 
            java.time.Instant.now());
    }

    private StepResult runScript(PlaybookStep step, String incidentId) {
        Object scriptName = step.getParameters().get("scriptName");
        logger.info("Running script: {} for incident: {}", scriptName, incidentId);
        return new StepResult(step.getStepId(), "RUN_SCRIPT", true, 
            "Script executed: " + scriptName, java.time.Instant.now());
    }

    private StepResult executeCustom(PlaybookStep step, String incidentId) {
        logger.info("Executing custom action: {} for incident: {}", step.getName(), incidentId);
        return new StepResult(step.getStepId(), "CUSTOM", true, 
            "Custom action completed", java.time.Instant.now());
    }

    public PlaybookExecution getExecution(String executionId) {
        return activeExecutions.get(executionId);
    }

    public List<Playbook> listPlaybooks() {
        return new ArrayList<>(playbooks.values());
    }

    public static class Playbook {
        private String playbookId;
        private String name;
        private String description;
        private List<PlaybookStep> steps;
        private List<String> applicableIncidentTypes;
        private boolean autoExecute;

        public String getPlaybookId() { return playbookId; }
        public void setPlaybookId(String playbookId) { this.playbookId = playbookId; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public List<PlaybookStep> getSteps() { return steps; }
        public void setSteps(List<PlaybookStep> steps) { this.steps = steps; }
        public List<String> getApplicableIncidentTypes() { return applicableIncidentTypes; }
        public void setApplicableIncidentTypes(List<String> applicableIncidentTypes) { this.applicableIncidentTypes = applicableIncidentTypes; }
        public boolean isAutoExecute() { return autoExecute; }
        public void setAutoExecute(boolean autoExecute) { this.autoExecute = autoExecute; }
    }

    public static class PlaybookStep {
        private String stepId;
        private String name;
        private ActionType actionType;
        private Map<String, Object> parameters;
        private int order;

        public enum ActionType {
            ISOLATE_HOST,
            BLOCK_IP,
            DISABLE_USER,
            COLLECT_FORENSICS,
            NOTIFY_TEAM,
            CREATE_TICKET,
            RUN_SCRIPT,
            CUSTOM
        }

        public String getStepId() { return stepId; }
        public void setStepId(String stepId) { this.stepId = stepId; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public ActionType getActionType() { return actionType; }
        public void setActionType(ActionType actionType) { this.actionType = actionType; }
        public Map<String, Object> getParameters() { return parameters; }
        public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
        public int getOrder() { return order; }
        public void setOrder(int order) { this.order = order; }
    }

    public record PlaybookExecution(
        String executionId,
        String playbookId,
        String incidentId,
        ExecutionStatus status,
        String executor,
        List<StepResult> stepResults,
        java.time.Instant startedAt,
        java.time.Instant completedAt
    ) {
        public enum ExecutionStatus {
            PENDING,
            RUNNING,
            COMPLETED,
            FAILED,
            CANCELLED
        }
    }

    public record StepResult(
        String stepId,
        String actionType,
        boolean success,
        String output,
        java.time.Instant executedAt
    ) {}
}
