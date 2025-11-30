# Sentinel Hub

Security operations platform for threat detection, incident response, and vulnerability management.

## Overview

Sentinel Hub is a comprehensive security operations platform designed to detect, investigate, and respond to security threats across cloud-native and hybrid infrastructure. It integrates with leading SIEM and EDR solutions to provide unified visibility and automated response capabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Sentinel Hub Platform                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Detection  │  │   Incident   │  │   Vulnerability      │  │
│  │    Engine    │  │  Management  │  │    Management        │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────┴─────────────────┴──────────────────────┴───────────┐  │
│  │           SIEM Integration Layer                           │  │
│  │         (Splunk, Azure Sentinel, QRadar)                   │  │
│  └─────────────────────────────┬─────────────────────────────┘  │
│                                │                                │
│  ┌─────────────────────────────┴─────────────────────────────┐  │
│  │           EDR Integration Layer                            │  │
│  │         (CrowdStrike, SentinelOne)                         │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Capabilities

### Threat Detection

- **Detection Rules**: Signature-based, anomaly-based, behavioral, and threat intelligence rules
- **Real-time Evaluation**: Stream processing of security events with sub-second detection
- **Threat Hunting**: Ad-hoc query capabilities for proactive threat hunting
- **Alert Correlation**: Intelligent correlation of related alerts to reduce noise

### Incident Response

- **Incident Management**: Full lifecycle management from detection to resolution
- **Response Playbooks**: Automated response workflows with customizable actions
- **Escalation Workflows**: Automatic escalation based on severity and SLA
- **Timeline Tracking**: Detailed audit trail of all incident activities

### Vulnerability Management

- **Vulnerability Tracking**: CVE-based vulnerability database with CVSS scoring
- **Risk Prioritization**: Critical vulnerability identification and tracking
- **Remediation Workflow**: End-to-end remediation tracking with assignment
- **Metrics & Trends**: Comprehensive dashboards and trend analysis

### Security Integrations

- **SIEM Integration**: Native integration with Splunk, Azure Sentinel, and QRadar
- **EDR Integration**: Direct integration with CrowdStrike Falcon and SentinelOne
- **Automated Response**: Host isolation, file quarantine, and process termination

## Technology Stack

- **Runtime**: Java 17
- **Framework**: Spring Boot 3.2.4 with Spring Security
- **Search**: Elasticsearch 8.12.2
- **Stream Processing**: Apache Kafka 3.7.0
- **Database**: PostgreSQL with Flyway migrations
- **Observability**: Micrometer, Prometheus

## Getting Started

### Prerequisites

- Java 17 or later
- Maven 3.8+
- PostgreSQL 14+
- Elasticsearch 8.12+
- Apache Kafka 3.7+

### Configuration

Edit `src/main/resources/application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/sentinelhub
    username: sentinel
    password: ${DB_PASSWORD:sentinel}
  security:
    user:
      name: ${SECURITY_ADMIN_USER:admin}
      password: ${SECURITY_ADMIN_PASSWORD:admin123}

sentinelhub:
  elasticsearch:
    enabled: true
    hosts: localhost:9200
    username: elastic
    password: ${ELASTIC_PASSWORD:changeme}
  siem:
    enabled: true
    integration-type: splunk
    splunk:
      hec-url: ${SPLUNK_HEC_URL:}
      hec-token: ${SPLUNK_HEC_TOKEN:}
  edr:
    enabled: true
    integration-type: crowdstrike
    crowdstrike:
      client-id: ${CROWDSTRIKE_CLIENT_ID:}
      client-secret: ${CROWDSTRIKE_CLIENT_SECRET:}
      base-url: ${CROWDSTRIKE_BASE_URL:}
  detection:
    rules-refresh-interval-seconds: 60
    alert-threshold: 0.7
```

### Building

```bash
mvn clean package
```

### Running

```bash
java -jar target/sentinel-hub-1.0.0.jar
```

## API Reference

### Detection APIs

```bash
# Create a detection rule
POST /api/v1/detection/rules
Content-Type: application/json

{
  "ruleId": "brute-force-detection",
  "name": "Brute Force Login Detection",
  "description": "Detects multiple failed login attempts",
  "type": "ANOMALY_BASED",
  "severity": "HIGH",
  "query": "type=AUTHENTICATION AND success=false",
  "evaluationWindow": "PT5M",
  "threshold": 5,
  "dataSource": ["auth-logs"],
  "enabled": true,
  "tags": ["authentication", "brute-force"],
  "mitigation": "Block source IP and notify security team"
}

# Ingest a security event
POST /api/v1/detection/events
Content-Type: application/json

{
  "eventId": "evt-001",
  "type": "AUTHENTICATION",
  "source": "auth-service",
  "sourceIp": "192.168.1.100",
  "userId": "user@example.com",
  "hostname": "workstation-01",
  "severity": "MEDIUM",
  "properties": {
    "success": false,
    "failureReason": "invalid_password"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}

# Execute a threat hunt
POST /api/v1/detection/hunt
Content-Type: application/json

{
  "name": "Suspicious IP Hunt",
  "indicators": ["192.168.1.100", "10.0.0.50"],
  "timeRange": "PT24H",
  "analyst": "analyst@example.com"
}
```

### Incident Management APIs

```bash
# Create an incident
POST /api/v1/incidents
Content-Type: application/json

{
  "title": "Suspected Brute Force Attack",
  "severity": "HIGH",
  "priority": "P2",
  "relatedAlertIds": ["alert-001", "alert-002"],
  "attackVector": "CREDENTIAL_THEFT",
  "description": "Multiple failed login attempts detected",
  "affectedSystems": ["auth-service", "user-portal"],
  "assignedTo": "security-analyst",
  "tags": ["authentication", "brute-force"]
}

# Update incident status
POST /api/v1/incidents/{incidentId}/status?status=INVESTIGATING&updatedBy=analyst

# Escalate incident
POST /api/v1/incidents/{incidentId}/escalate?reason=SLA_breach&escalatedBy=manager

# Execute response playbook
POST /api/v1/incidents/playbooks/{playbookId}/execute?incidentId=INC-001&executor=analyst
```

### Vulnerability Management APIs

```bash
# Register a vulnerability
POST /api/v1/vulnerabilities
Content-Type: application/json

{
  "vulnerabilityId": "vuln-001",
  "cveId": "CVE-2024-1234",
  "title": "Remote Code Execution in Web Framework",
  "description": "A critical RCE vulnerability...",
  "cvss": {
    "baseScore": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "severity": "CRITICAL"
  },
  "affectedAsset": "web-server-01",
  "affectedComponent": "web-framework",
  "affectedVersion": "2.1.0",
  "remediation": "Upgrade to version 2.2.0 or later"
}

# Get vulnerability metrics
GET /api/v1/vulnerabilities/metrics

# Remediate a vulnerability
POST /api/v1/vulnerabilities/{vulnerabilityId}/remediate?remediatedBy=ops-team
```

## Detection Rule Types

| Type | Description | Use Case |
|------|-------------|----------|
| SIGNATURE_BASED | Pattern matching against known threats | Malware signatures, known bad IPs |
| ANOMALY_BASED | Statistical deviation from baseline | Unusual login patterns, data exfiltration |
| BEHAVIORAL | Sequence of actions analysis | Lateral movement, privilege escalation |
| THREAT_INTEL | Integration with threat feeds | Known C2 servers, malicious domains |
| COMPLIANCE | Policy violation detection | Missing security controls, config drift |

## Response Playbook Actions

- **ISOLATE_HOST**: Network isolation of compromised hosts
- **BLOCK_IP**: Firewall rule creation for IP blocking
- **DISABLE_USER**: Account disablement in identity provider
- **COLLECT_FORENSICS**: Memory and disk image collection
- **NOTIFY_TEAM**: Slack/Teams/PagerDuty notifications
- **CREATE_TICKET**: ServiceNow/Jira ticket creation
- **RUN_SCRIPT**: Custom script execution for remediation

## Monitoring

### Health Endpoints

- `/actuator/health` - Overall health status
- `/actuator/metrics` - Application metrics
- `/actuator/prometheus` - Prometheus metrics endpoint

### Key Metrics

- `security.events.processed` - Total security events processed
- `detection.rules.triggered` - Detection rule triggers
- `alerts.active.count` - Active alert count
- `incidents.open.count` - Open incidents by severity
- `vulnerabilities.critical.count` - Critical vulnerabilities
- `response.playbook.executions` - Playbook execution count

## Security Considerations

1. **Authentication**: All API endpoints require authentication via Spring Security
2. **Authorization**: Role-based access control for sensitive operations
3. **Audit Logging**: All security-relevant actions are logged
4. **Data Encryption**: TLS for data in transit, encryption at rest supported
5. **Secret Management**: External secret injection via environment variables

## License

Proprietary - All rights reserved.
