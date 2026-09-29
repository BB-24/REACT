# Cost Model

**Purpose**: Estimate and track costs for the Automated Cloud Forensic Pipeline (AACFP) per incident and per month.

**Owner**: Person 1 (@BB-24) — Cloud Orchestration & Infrastructure Security

---

## 1. Monthly Baseline Costs (Standby)

| Component | SKU / Tier | Qty | Est. Monthly Cost (USD) | Notes |
|-----------|------------|-----|------------------------|-------|
| **Logic App** | Standard (WS1) | 1 | $60.00 | Fixed monthly; includes 1M actions |
| **Function App** | Consumption (Y1) | 1 | ~$5.00 | Idle cost (storage, minimal executions) |
| **Storage Account** | Standard LRS (100 GB) | 1 | $18.00 | Function runtime + App Insights logs |
| **App Insights** | Pay-as-you-go (1 GB/day) | 1 | $70.00 | Logs, metrics, live metrics |
| **NSG** | Standard | 0 (created per incident) | $0.00 | No cost until created |
| **Public IP (Logic App)** | Basic | 1 | $3.65 | Inbound webhook endpoint |
| **Total Baseline** | | | **~$156.65/month** | |

> **DR Standby** (duplicate in secondary region): **~$313.30/month total**

---

## 2. Per-Incident Variable Costs

| Cost Driver | Unit | Rate (USD) | Typical Usage | Cost per Incident |
|-------------|------|------------|---------------|-------------------|
| **Function Executions** | Per 1M executions | $0.20 | 1–5 executions | <$0.01 |
| **Function Execution Time** | GB-seconds | $0.000016 | 5s × 1.5 GB = 7.5 GB-s | ~$0.0001 |
| **Logic App Actions** | Per 1M actions | $0.025 | ~15 actions (parse, HTTP×5, until loop×10) | ~$0.0004 |
| **Isolation NSG** | Per NSG-hour | $0.015/hour | 4–24 hours (until restoration) | $0.06–$0.36 |
| **NSG Rules** | Per rule | Included | 4 rules per NSG | $0.00 |
| **Outbound Data (Function → ARM)** | Per GB | $0.087 | <1 MB | <$0.01 |
| **App Insights Ingestion** | Per GB | $2.30 | ~50 KB per incident | <$0.01 |
| **Total Per Incident** | | | | **~$0.07–$0.40** |

---

## 3. Cost Scenarios

### Scenario A: Low Volume (10 incidents/month)
| Category | Monthly Cost |
|----------|--------------|
| Baseline | $156.65 |
| Variable (10 × $0.20 avg) | $2.00 |
| **Total** | **~$158.65** |

### Scenario B: Medium Volume (100 incidents/month)
| Category | Monthly Cost |
|----------|--------------|
| Baseline | $156.65 |
| Variable (100 × $0.20 avg) | $20.00 |
| NSG hours (100 × 12h avg × $0.015) | $18.00 |
| **Total** | **~$194.65** |

### Scenario C: High Volume (1,000 incidents/month)
| Category | Monthly Cost |
|----------|--------------|
| Baseline | $156.65 |
| Variable (1,000 × $0.20 avg) | $200.00 |
| NSG hours (1,000 × 12h avg × $0.015) | $180.00 |
| Logic App actions (15,000 actions) | $0.38 |
| App Insights (50 MB) | $0.12 |
| **Total** | **~$537.15** |

---

## 4. Cost Optimization Recommendations

| Optimization | Savings | Effort |
|--------------|---------|--------|
| **Logic App Consumption Tier** | $60 → ~$5/month (if < 100 runs) | Low (change SKU) |
| **App Insights Daily Cap** | Limit to 500 MB/day → ~$35/month | Low (set cap) |
| **Storage LRS → ZRS** | Minor durability gain, same cost | Low |
| **Delete Isolation NSGs Post-Incident** | Avoid $0.015/hr accumulation | Medium (automation) |
| **Reserved Capacity (if predictable)** | Up to 30% on Logic App | High (commitment) |

---

## 5. Cost Allocation & Tagging

All resources tagged for chargeback:

```bicep
param tags object = {
  Application: 'AACFP'
  Project: 'Forensic-Containment-Pipeline'
  Environment: 'Production'
  CostCenter: 'Security-Operations'
  Owner: 'BB-24'
}
```

**Azure Cost Management Query**:
```kql
CostManagementResources
| where tags['Application'] == 'AACFP'
| summarize TotalCost = sum(cost) by bin(timestamp, 1d), tags['CostCenter']
| render timechart
```

---

## 6. Budget & Alerts

```bash
# Create budget for AACFP resource group
az consumption budget create \
  --budget-name "AACFP-Monthly-Budget" \
  --amount 500 \
  --time-grain Monthly \
  --start-date 2026-01-01 \
  --end-date 2026-12-31 \
  --category Cost \
  --resource-group-filter Forensic-Enclave-RG \
  --notification-key "Over80" \
  --notification-enabled true \
  --operator GreaterThan \
  --threshold 80 \
  --contact-emails "security-ops@company.com,bb24@company.com"
```

---

## 7. Cost Tracking per Incident

**Proposed**: Add `IncidentID` tag to isolation NSG at creation (Function App):

```python
# In _create_isolation_nsg()
tags = {
    "Application": "AACFP",
    "IncidentID": incident.incident_id,
    "CreatedBy": "NetworkContainmentFunction",
    "AutoDeleteAfter": "24h"  # For cleanup automation
}
```

Then query:
```kql
CostManagementResources
| where tags['IncidentID'] == 'INC-2026-0001'
| summarize IncidentCost = sum(cost)
```

---

## 8. Related Documents

- [Disaster Recovery](./disaster-recovery.md) — DR standby costs
- [Restoration Runbook](./restoration-runbook.md) — NSG cleanup reduces cost
- [Security Baseline](./security-baseline.md) — Required tags for cost allocation
- [Orchestration Overview](./orchestration.md) — Architecture context

---

## 9. Review Cadence

| Review | Frequency | Owner |
|--------|-----------|-------|
| Cost vs Budget | Monthly | @BB-24 |
| Per-Incident Cost Analysis | Quarterly | @BB-24 + Finance |
| SKU Optimization Review | Semi-annually | @BB-24 + Platform |