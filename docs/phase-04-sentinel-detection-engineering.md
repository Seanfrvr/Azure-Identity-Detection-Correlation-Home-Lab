# Phase 04: Sentinel Detection Engineering

## Objective

Phase 04 converted the Phase 03 investigation into a reusable Microsoft Sentinel scheduled analytics rule.

The investigation had already established the behaviour pattern:

```text
User Administrator assigned
        ↓
same identity
        ↓
creates another Entra user
        ↓
within 60 minutes
```

The goal was to detect that sequence generically rather than write a query that only matched the known lab identities.

## Historical Validation

The candidate detection was first tested against the existing Phase 02 telemetry. The query contained no references to `case-user` or `case-secondary`.

It joined successful `Add member to role` events with successful `Add user` events on the same identity and required the second action to occur within 60 minutes of elevation.

The historical test returned one match:

```text
Identity: case-user
Role: User Administrator
CreatedUser: case-secondary
TimeToAction: 00:36:11
```

![Historical detection validation](../images/phase4_01_historical_detection_validation.png)

This proved that the detection logic could reconstruct the known sequence without hardcoding the answer.

The detection is preserved in:

[`../detections/privilege-followed-by-user-creation.kql`](../detections/privilege-followed-by-user-creation.kql)

## Scheduled Rule Design

The deployed rule is named:

`Newly Elevated User Administrator Creates Cloud Identity`

The configuration uses a five minute query frequency and a 65 minute lookback period. The 65 minute period allows the rule to correlate a 60 minute privilege window while still accounting for the five minute execution interval.

The rule is Medium severity and maps to the Persistence and Privilege Escalation tactics. Sentinel's API accepted the parent ATT&CK techniques `T1098` and `T1136`.

The rule also maps the elevated identity as an Account entity and carries the assigned role, created user, and time to action as custom details.

Incident creation is enabled.

## Deployment as Code

The Defender portal Analytics experience redirected back to the workspace list, so the rule was deployed through the official Microsoft SecurityInsights alert rule API using Azure Cloud Shell.

The deployment returned an enabled Scheduled rule with the intended frequency, lookback, severity, and display name.

![Sentinel rule API deployment](../images/phase4_02_sentinel_rule_api_deployment.png)

The deployment process is preserved as a reusable script:

[`../scripts/deploy-sentinel-rule.sh`](../scripts/deploy-sentinel-rule.sh)

The script does not contain subscription IDs, tenant IDs, tokens, passwords, or other secrets. It resolves the active subscription dynamically from the authenticated Azure CLI session.

## Rule Verification

After deployment, the rule was read back from Sentinel through the API rather than assuming that a successful creation response meant the final configuration was correct.

The returned configuration confirmed:

```text
Enabled: true
CreateIncident: true
Frequency: PT5M
Lookback: PT1H5M
Severity: Medium
Tactics: Persistence, PrivilegeEscalation
Techniques: T1098, T1136
```

![Deployed rule configuration](../images/phase4_03_deployed_rule_configuration.png)

This second API call verifies that the rule exists in Sentinel with the intended settings.

## Engineering Notes

The API validation process exposed two implementation details that were corrected before deployment.

First, the incident grouping object required fields such as `reopenClosedIncident`, `lookbackDuration`, and `matchingMethod` even though grouping itself was disabled.

Second, the Sentinel API rejected ATT&CK subtechnique notation in the `techniques` field and required parent technique IDs in `T####` format. The deployed rule therefore uses `T1098` and `T1136` while the more specific identity context remains part of the analyst writeup.

These were configuration corrections, not detection logic changes.

## Phase 04 Conclusion

**PROVEN:** The correlation query detects the historical privilege to user creation sequence without hardcoded lab identity names. The scheduled Sentinel rule was deployed successfully through the API. Sentinel reads the rule back as enabled with incident creation turned on.

**SUPPORTED:** The rule is suitable for live validation because it correlates two otherwise legitimate administrative events around the same identity and a defined time window.

**NOT YET PROVEN:** The deployed rule has not yet been validated against a new event sequence generated after the rule existed. That is the purpose of Phase 05.

Phase 04 therefore closes with a deployed, enabled, reusable Sentinel analytic rule ready for controlled replay.
