# Phase 03: KQL Investigation & Timeline Reconstruction

## Objective

Phase 03 treated the Phase 02 activity as an investigation rather than a known answer. The goal was to widen the search around `case-user`, identify which surrounding events mattered, separate setup activity from the security relevant sequence, and then reconstruct the final timeline with a measurable time gap.

The investigation started broad because a useful detection cannot be designed from two hand picked events alone. The analyst first needed to understand what else happened around the identity before and after elevation.

## Broad Identity Hunt

The initial hunt pulled activity where `case-user` appeared either as the actor or the target. This surfaced more than the two events already known from Phase 02. The surrounding window included password resets, password profile changes, security information registration, user updates, password validation, the role assignment, and the later creation of `case-secondary`.

Those additional events mattered because they demonstrated an important detection engineering problem: not every event near a suspicious sequence is itself suspicious.

The password and registration events were expected consequences of preparing and signing in with a newly created lab identity. Treating them as malicious would have produced a noisy and misleading investigation.

## Triage Classification

A second KQL pass classified the events into `Primary finding`, `Setup context`, and `Other context`.

The two primary findings were:

```text
04:32:54 UTC
lab-admin → Add member to role → case-user → success

05:09:05 UTC
case-user → Add user → case-secondary → success
```

The surrounding password and security registration events remained visible as setup context rather than being deleted from the investigation. This preserved the full story while preventing benign preparation activity from dominating the finding.

![Identity activity triage](../images/phase3_01_identity_activity_triage.png)

The query used for this view is preserved in:

[`detections/phase3_identity_activity_triage.kql`](../detections/phase3_identity_activity_triage.kql)

## Timeline Reconstruction

The final reconstruction query isolated the privilege assignment and the sensitive follow on identity action, ordered them chronologically, and calculated the elapsed time between them.

The result showed that `case-user` received the `User Administrator` role and then created `case-secondary` **36 minutes and 11 seconds later**.

![Timeline reconstruction](../images/phase3_02_timeline_reconstruction.png)

The reconstruction query is preserved in:

[`detections/phase3_timeline_reconstruction.kql`](../detections/phase3_timeline_reconstruction.kql)

## Analyst Finding

### Proven

The Entra audit evidence proves that `case-user` received the built in `User Administrator` role successfully. It also proves that the same identity later created `case-secondary` successfully. The elapsed time between the two events was approximately 36 minutes and 11 seconds.

### Supported

The sequence is security relevant because a newly elevated identity performed a sensitive identity management action shortly after receiving additional privilege. In a real environment this would justify analyst review and is suitable for correlation based detection logic.

### Not Proven

The evidence does not prove account compromise, malicious intent, unauthorized persistence, credential theft, or attacker control. The activity was intentionally generated as part of the lab.

## Detection Engineering Implication

The investigation changed the detection question from:

> Did a role assignment occur?

into:

> Did an identity receive a selected administrative role and then perform a sensitive identity management action within a meaningful time window?

That distinction is the main outcome of Phase 03. A role assignment alone is an administrative event. A user creation alone is also an administrative event. The value comes from correlating the two actions around the same identity and time window while retaining enough surrounding context for an analyst to judge whether the sequence is expected.

Phase 04 will convert this investigation logic into a Microsoft Sentinel analytic rule and test whether the sequence can generate a useful alert without treating every administrative action as malicious.
