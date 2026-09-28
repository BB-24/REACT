# Incident workflow testing

After deploying `logic-app.bicep`, copy the HTTP POST URL from the
`Incident_Webhook` trigger. Use a full VM resource ID for `TargetVM`; it lets
the containment Function reliably identify the VM's primary NIC.

```bash
curl --request POST "$LOGIC_APP_WEBHOOK_URL" \
  --header "Content-Type: application/json" \
  --data '{
    "IncidentID": "INC-2026-0001",
    "TargetVM": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/Compromised-Environment-RG/providers/Microsoft.Compute/virtualMachines/suspicious-vm-01",
    "IPAddress": "203.0.113.25",
    "SubscriptionID": "11111111-1111-1111-1111-111111111111",
    "IncidentSeverity": "High"
  }'
```

In Postman, create a `POST` request to the same URL, set `Content-Type` to
`application/json`, and select **Body → raw → JSON** with the payload above.
For independently testing the Function endpoint, replace the URL with
`https://<function-app>.azurewebsites.net/api/NetworkContainment?code=<function-key>`.

The Function App identity requires **Network Contributor** over the resource
group that contains the target NIC and the isolation NSG. Set
`REGION_NAME` to the NSG region and, when evidence is on Storage Private
Endpoints, set `EVIDENCE_STORAGE_PRIVATE_ENDPOINT_PREFIXES` to their
comma-separated IP/CIDR addresses.
