# NSG Restoration Runbook

**Purpose**: Restore a compromised VM's original Network Security Group after forensic analysis is complete and the incident is closed.

**Owner**: Person 1 (@BB-24) — Cloud Orchestration & Infrastructure Security

---

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| Azure CLI | `az` v2.50+ with `network` extension |
| Permissions | **Network Contributor** on `Compromised-Environment-RG` (or NIC/NSG level) |
| Information | `IncidentID`, original `NSG resource ID` (captured during containment) |

---

## 2. Locate the Original NSG

The original NSG ID is returned by the `NetworkContainment` Function in its success response:

```json
{
  "status": "Contained",
  "IncidentID": "INC-2026-0001",
  "NetworkInterface": "/subscriptions/.../networkInterfaces/vm-nic",
  "IsolationNSG": "Forensic-Isolation-NSG-INC-2026-0001",
  "PreviousNSGId": "/subscriptions/.../resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkSecurityGroups/original-nsg"
}
```

If you missed it, retrieve from Logic App run history:
1. Azure Portal → Logic App `aacfp-incident-response` → **Runs History**
2. Find the run for your `IncidentID`
3. Expand `Call_Network_Containment` → **Outputs** → `PreviousNSGId`

---

## 3. Manual Restoration (Azure CLI)

```bash
# Variables - REPLACE WITH YOUR VALUES
INCIDENT_ID="INC-2026-0001"
TARGET_VM_RG="Compromised-Environment-RG"
TARGET_VM_NAME="suspicious-vm-01"
ORIGINAL_NSG_ID="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Network/networkSecurityGroups/original-nsg"

# 1. Get the VM's primary NIC
NIC_ID=$(az vm show \
  --resource-group "$TARGET_VM_RG" \
  --name "$TARGET_VM_NAME" \
  --query "networkProfile.networkInterfaces[?primary==\`true\`].id | [0]" \
  -o tsv)

if [ -z "$NIC_ID" ]; then
  NIC_ID=$(az vm show \
    --resource-group "$TARGET_VM_RG" \
    --name "$TARGET_VM_NAME" \
    --query "networkProfile.networkInterfaces[0].id" \
    -o tsv)
fi

NIC_RG=$(echo "$NIC_ID" | cut -d'/' -f5)
NIC_NAME=$(echo "$NIC_ID" | cut -d'/' -f9)

echo "Restoring NIC: $NIC_NAME in RG: $NIC_RG"
echo "Original NSG: $ORIGINAL_NSG_ID"

# 2. Reattach original NSG
az network nic update \
  --resource-group "$NIC_RG" \
  --name "$NIC_NAME" \
  --network-security-group "$ORIGINAL_NSG_ID"

# 3. Verify
az network nic show \
  --resource-group "$NIC_RG" \
  --name "$NIC_NAME" \
  --query "networkSecurityGroup.id" \
  -o tsv
```

---

## 4. Automated Restoration (Recommended: Azure Function)

> **Future Enhancement**: A `RestoreContainment` Function should be added to the codebase (see [GitHub Issue #TODO](https://github.com/.../issues/TODO)).

**Proposed Function Signature**:
```http
POST /api/RestoreContainment
Content-Type: application/json

{
  "IncidentID": "INC-2026-0001",
  "TargetVM": "/subscriptions/.../virtualMachines/suspicious-vm-01",
  "OriginalNSGId": "/subscriptions/.../networkSecurityGroups/original-nsg"
}
```

**Logic**:
1. Validate IncidentID exists in forensic ledger (Person 3 Cosmos DB)
2. Verify caller has `IncidentResponder` role
3. Perform NIC NSG swap back to `OriginalNSGId`
4. Optionally delete isolation NSG (`Forensic-Isolation-NSG-<IncidentID>`)
5. Emit audit event to Log Analytics / Sentinel

---

## 5. Cleanup Isolation NSG (Optional)

After restoration, the isolation NSG can be deleted to avoid clutter:

```bash
ISOLATION_NSG="Forensic-Isolation-NSG-$INCIDENT_ID"
ISOLATION_NSG_RG="$TARGET_VM_RG"  # Created in same RG as NIC

az network nsg delete \
  --resource-group "$ISOLATION_NSG_RG" \
  --name "$ISOLATION_NSG" \
  --yes
```

> **Note**: Do NOT delete if the NSG is still attached to other NICs or if you need it for audit trail.

---

## 6. Verification Checklist

| Step | Verification |
|------|--------------|
| ✅ NIC shows original NSG | `az network nic show ... --query networkSecurityGroup.id` matches `OriginalNSGId` |
| ✅ SSH/RDP restored | New connection to VM succeeds |
| ✅ Isolation NSG detached | `az network nsg show --name Forensic-Isolation-NSG-<ID>` shows no associated NICs |
| ✅ Audit logged | Incident record in Cosmos DB updated with `RestorationTimestamp` |

---

## 7. Emergency: If Original NSG Was Deleted

If `PreviousNSGId` points to a deleted NSG:

1. **Recreate from ARM Template**: Export original NSG template from backup or policy
2. **Apply Baseline NSG**: Apply organization's standard baseline NSG (allow management ports, deny internet)
3. **Document Exception**: Record in incident ticket that original NSG was unavailable

---

## 8. Related Documents

- [Disaster Recovery](./disaster-recovery.md) — Region failover for orchestrator components
- [Security Baseline](./security-baseline.md) — Required NSG rules and tags
- [Orchestration Overview](./orchestration.md) — Architecture and Phase 4 validation

---

## 9. Contact

| Role | Contact |
|------|---------|
| Cloud Orchestration (Person 1) | @BB-24 |
| Serverless Functions (Person 2) | @gitforg |
| Evidence Analysis (Person 3) | @jyeshthachouhan14 |