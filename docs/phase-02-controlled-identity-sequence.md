# Phase 02: Controlled Identity Sequence

## Objective

Phase 02 introduced the first security relevant identity sequence into the lab. The goal was to create a simple but meaningful chain that could later be investigated and detected as one sequence rather than as two unrelated audit events.

The scenario used `case-user`, which began as a normal Entra identity. The account was assigned the built in `User Administrator` role and then used to create a second identity named `case-secondary`.

The working hypothesis was:

> A newly elevated identity performs sensitive identity management activity shortly afterward.

This was a controlled lab action. It does not represent unauthorized access or a real compromise.

## Privilege Assignment

The first step was to assign `User Administrator` to `case-user`. Entra recorded the change as a successful `RoleManagement` event with the activity `Add member to role`.

![User Administrator role assignment](../images/phase2_01_user_administrator_role_assignment.png)

The role metadata showed `Role.DisplayName` as `User Administrator`, confirming the exact privilege that was assigned.

The same event was then recovered inside Microsoft Sentinel from the `AuditLogs` table.

![Sentinel role assignment KQL](../images/phase2_02_sentinel_role_assignment_kql.png)

This established that the privilege change was present in both the native Entra audit view and the Sentinel investigation layer.

## Sensitive Follow On Action

After the role assignment, `case-user` signed in separately and used the new privilege to create `case-secondary`.

A KQL query extracted the actor and target while removing the tenant domain from the displayed values:

```kql
AuditLogs
| where OperationName == "Add user"
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend Actor = tostring(split(ActorUPN, "@")[0])
| extend Target = tostring(split(TargetUPN, "@")[0])
| project TimeGenerated, Actor, OperationName, Target, Result, Category
| order by TimeGenerated desc
```

The result showed:

```text
Actor: case-user
OperationName: Add user
Target: case-secondary
Result: success
Category: UserManagement
```

![case-user creates case-secondary](../images/phase2_03_case_user_creates_secondary_kql.png)

This is stronger than a simple portal screenshot because the event directly identifies the initiating identity, the action, and the target from the ingested audit telemetry.

## Sequence Correlation

The final Phase 02 query brought the role assignment and the user creation into one chronological view.

```kql
union
(
    AuditLogs
    | where OperationName == "Add member to role"
    | mv-expand TR = TargetResources
    | extend IdentityUPN = tostring(TR.userPrincipalName)
    | mv-expand P = TR.modifiedProperties
    | where tostring(P.displayName) == "Role.DisplayName"
    | extend Identity = tostring(split(IdentityUPN, "@")[0])
    | extend Detail = trim(@'"', tostring(P.newValue))
    | where Identity == "case-user"
    | project TimeGenerated,
              Stage = "Privilege assigned",
              Identity,
              Detail,
              Result
),
(
    AuditLogs
    | where OperationName == "Add user"
    | extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
    | extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
    | extend Identity = tostring(split(ActorUPN, "@")[0])
    | extend Target = tostring(split(TargetUPN, "@")[0])
    | where Identity == "case-user" and Target == "case-secondary"
    | project TimeGenerated,
              Stage = "Sensitive identity action",
              Identity,
              Detail = strcat("Created ", Target),
              Result
)
| order by TimeGenerated asc
```

![Privilege to identity action timeline](../images/phase2_04_privilege_to_identity_action_timeline.png)

The query reconstructed the sequence as:

```text
Privilege assigned
case-user
User Administrator
success

Sensitive identity action
case-user
Created case-secondary
success
```

This correlation view is the main result of Phase 02. It proves that the same identity received an administrative role and later performed a sensitive identity management action.

## What the Evidence Proves

The evidence proves that `case-user` received the `User Administrator` role, that the role assignment reached Sentinel, and that the same identity later created `case-secondary` successfully.

The evidence also proves that both events can be reconstructed into one ordered timeline using KQL.

## What the Evidence Does Not Prove

The sequence does not prove malicious intent, account compromise, persistence, or unauthorized privilege escalation. Every action in this phase was performed deliberately inside the lab.

The security value comes from the behaviour pattern itself. In a real environment, a newly elevated identity performing sensitive identity management activity shortly afterward would be worth analyst review and could justify correlation based detection logic.

## Phase 02 Result

Phase 02 closes with a validated event chain that is suitable for deeper investigation in Phase 03 and later conversion into Sentinel analytic logic.

The investigation query used for the final sequence has been preserved in:

```text
detections/identity-activity-hunt.kql
```
