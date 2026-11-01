# P1-P2 Logic App to containment integration test

The collection in [`tests/postman/REACT-P1-P2-Containment.postman_collection.json`](../tests/postman/REACT-P1-P2-Containment.postman_collection.json)
validates the incident webhook, Logic App parsing, Function invocation, and the
`Contained` response contract. Its payload is synthetic; it does not represent a
real Sentinel incident.

## Before running

1. Deploy the Function App and Logic App from the current infrastructure
   templates. Confirm the Function App exposes the v2 route
   `/api/NetworkContainment` and that the Logic App uses the deployed Function
   URL.
2. Provision a disposable VM named `react-demo-*` in the dedicated resource
   group `rg-react-p1p2-demo`. Confirm that it is not tagged
   `Critical-Infrastructure`, record its current NIC/NSG association, and ensure
   you can restore the original NSG after the demo. This Function replaces the
   NIC's NSG and can disconnect the VM.
3. Give the Function App identity the required Network Contributor access only
   over the demo resources. Verify the configured region and any required
   private endpoint egress prefixes before running.
4. Import the Postman collection and
   [`tests/postman/REACT-P1-P2-Demo.postman_environment.json`](../tests/postman/REACT-P1-P2-Demo.postman_environment.json).
   Set `logicAppUrl` to the Logic App `Incident_Webhook` URL, and set
   `subscriptionId` and `targetVmResourceId` to the dedicated demo VM's actual
   values. Keep `allowContainment` set to `false` until the target is reviewed.
   The Logic App URL contains a signed trigger credential: treat it as a secret
   and do not export it in a shared environment.

## Run and verify

1. Establish an authorized SSH session and an HTTP health check against the
   disposable VM; record both baseline results. Confirm the VM is running and
   that the original NIC/NSG association is recorded for restoration.
2. In Postman, choose the configured demo environment and inspect the request
   body. The request must remain `High` severity with `TestMode: true`.
3. Change `allowContainment` to `true` only after confirming the dedicated demo
   target and current NSG. The collection pre-request script skips execution
   unless that opt-in is enabled and the target resource ID matches the exact
   demo resource group and VM-name prefix.
4. Send the request. The Logic App's TestMode branch returns the Function
   response directly and skips acquisition and analysis. The collection checks
   for HTTP 200, `status: "Contained"`, a non-empty `IsolationNSG`, and the
   presence of `PreviousNSGId` (which can be `null` if there was no prior NSG).
5. From the same authorized client, verify SSH and HTTP no longer reach the VM.
   Confirm the VM remains running through the Azure control plane; do not
   attempt to recover access by restarting or deallocating it.
6. Verify the corresponding Logic App run history shows `Parse_Incident`,
   `Call_Network_Containment`, and `Return_Containment_Result` succeeded. Keep
   the run ID and timestamp with the test record.
7. Export the Postman Runner results as JSON and save the raw export in the
   team's access-controlled evidence store. Before sharing or committing any
   sanitized excerpt, remove the signed Logic App URL, function keys, private
   resource identifiers, subscription IDs, and any other sensitive values.
   Do not add raw run logs or environment exports to this repository.
8. Restore the previously recorded NSG association through the approved
   recovery procedure, then verify SSH and HTTP connectivity again. Confirm
   the isolation NSG is no longer attached before ending the test.

The repository contains the runnable collection and this evidence procedure,
not a completed Azure execution log. A real Postman export can only be produced
after an authorized test deployment and disposable VM are available.
