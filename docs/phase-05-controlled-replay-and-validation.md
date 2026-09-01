# Phase 05: Controlled Replay, Tuning and Final Validation

Phase 05 tested whether the deployed Sentinel rule could detect a brand new identity sequence generated after the rule already existed.

The objective was simple: replay the behaviour without changing the underlying detection hypothesis, observe what Sentinel produced, fix any real engineering issue that appeared, and validate the tuned result with a second fresh replay.

## First Live Replay

`case-user` received the `User Administrator` role again and then created a new identity named `case-validation`.

Sentinel recovered the new user creation successfully.

```text
Actor: case-user
Operation: Add user
Target: case-validation
Result: success
```

![Validation replay telemetry](../images/phase5_01_validation_replay_case_validation.png)

The deployed scheduled rule then produced two `SecurityAlert` records for the same replay.

![Initial duplicate security alerts](../images/phase5_02_initial_duplicate_security_alerts.png)

Two Sentinel incidents were also created.

![Initial duplicate incidents](../images/phase5_03_initial_duplicate_incidents.png)

This was a genuine detection engineering issue. The rule ran every five minutes while searching a 65 minute lookback window, so the same newly ingested `Add user` event could be matched by more than one scheduled execution.

The duplicate was not hidden or removed from the project. It became the tuning problem for the final validation stage.

## Tuning Decision

The role assignment still needs the full 65 minute context because the detection asks whether a user was elevated within the previous hour.

The follow on `Add user` event does not need to be eligible during every overlapping scheduled run. The query was therefore changed so that the sensitive action is evaluated inside one ingestion slice:

```kql
| where ingestion_time() >= ago(10m)
| where ingestion_time() < ago(5m)
```

The role assignment remains searchable across the full lookback while the newly ingested user creation becomes eligible for one scheduled evaluation window.

The final tuned query is preserved in:

[`../detections/privilege-followed-by-user-creation.kql`](../detections/privilege-followed-by-user-creation.kql)

The existing Sentinel analytic rule was updated using the same rule identifier rather than creating a second detection.

![Tuned rule redeployment](../images/phase5_04_tuned_rule_redeployment.png)

## Final Retest

A second fresh sequence was then generated. `case-user` was elevated again and created `case-retest`.

The replay reached Sentinel successfully:

```text
Actor: case-user
Operation: Add user
Target: case-retest
Result: success
```

![Final retest telemetry](../images/phase5_05_final_retest_case_retest.png)

The tuned rule produced one new `SecurityAlert` record.

![Single alert after tuning](../images/phase5_06_single_alert_after_tuning.png)

The corresponding Sentinel incident query returned one new incident, Incident 3, with Medium severity and New status.

![Single incident after tuning](../images/phase5_07_single_incident_after_tuning.png)

The final validation result was therefore:

```text
1 fresh replay
      ↓
1 Sentinel alert
      ↓
1 Sentinel incident
```

## Analyst Conclusion

**PROVEN:** The generic Sentinel correlation rule detected a fresh sequence generated after the rule already existed. The first replay exposed duplicate alerting caused by overlapping scheduled evaluation windows. The query was tuned and redeployed. A second fresh replay produced one alert and one incident.

**SUPPORTED:** The final detection is suitable as a focused behavioural analytic for this lab because it correlates a privilege assignment with a sensitive follow on identity action around the same actor and a defined time window.

**NOT PROVEN:** The detection does not prove compromise, attacker control, malicious intent, or unauthorized persistence. Administrative workflows can produce similar activity, so analyst validation remains necessary in a real environment.

## Final Engineering Result

The project did not stop at "the query matched." It progressed through:

```text
telemetry validation
      ↓
controlled behaviour
      ↓
analyst investigation
      ↓
generic correlation logic
      ↓
API deployed Sentinel rule
      ↓
live replay
      ↓
duplicate alert discovery
      ↓
tuning
      ↓
fresh retest
      ↓
1 alert → 1 incident
```

That closes the technical validation of the lab.
