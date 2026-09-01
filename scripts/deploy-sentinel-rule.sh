#!/usr/bin/env bash
set -euo pipefail

# Phase 04: Deploy the Sentinel scheduled analytics rule through the Azure REST API.
# This script expects an authenticated Azure CLI session and deliberately does not
# contain subscription IDs, tenant IDs, credentials, tokens, or other secrets.

RG="rg-azure-identity-lab"
WS="law-azure-identity-lab"
RULE_ID="${RULE_ID:-$(uuidgen)}"
SUB_ID="$(az account show --query id -o tsv)"

QUERY_FILE="detections/privilege-followed-by-user-creation.kql"
RULE_FILE="rule.json"

if [[ ! -f "$QUERY_FILE" ]]; then
  echo "Missing $QUERY_FILE"
  exit 1
fi

jq -n --rawfile query "$QUERY_FILE" '
{
  kind: "Scheduled",
  properties: {
    displayName: "Newly Elevated User Administrator Creates Cloud Identity",
    description: "Detects a successful User Administrator role assignment followed by the same identity creating another Entra user within 60 minutes. This behavioral correlation is security relevant but does not by itself prove malicious intent.",
    severity: "Medium",
    enabled: true,
    tactics: ["Persistence", "PrivilegeEscalation"],
    techniques: ["T1098", "T1136"],
    query: $query,
    queryFrequency: "PT5M",
    queryPeriod: "PT1H5M",
    triggerOperator: "GreaterThan",
    triggerThreshold: 0,
    suppressionDuration: "PT1H",
    suppressionEnabled: false,
    eventGroupingSettings: { aggregationKind: "AlertPerResult" },
    entityMappings: [
      {
        entityType: "Account",
        fieldMappings: [
          { identifier: "Name", columnName: "IdentityName" },
          { identifier: "UPNSuffix", columnName: "IdentityUPNSuffix" }
        ]
      }
    ],
    customDetails: {
      AssignedRole: "Role",
      CreatedUser: "CreatedUser",
      TimeToAction: "TimeToAction"
    },
    incidentConfiguration: {
      createIncident: true,
      groupingConfiguration: {
        enabled: false,
        reopenClosedIncident: false,
        lookbackDuration: "PT5H",
        matchingMethod: "AllEntities",
        groupByEntities: [],
        groupByAlertDetails: [],
        groupByCustomDetails: []
      }
    }
  }
}' > "$RULE_FILE"

az rest \
  --method put \
  --url "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules/$RULE_ID?api-version=2025-09-01" \
  --headers "Content-Type=application/json" \
  --body "@$RULE_FILE"

echo "Rule deployed with ID: $RULE_ID"
