# REACT Live Azure Demo Presenter Guide

> **Live-system notice:** This walkthrough acts on real Azure resources. Use
> only pre-deployed, disposable demo VMs tagged `REACT-Demo=True`. Network
> containment changes NIC NSG associations; memory collection and disk
> snapshots create real evidence and can incur Azure charges.

## Before reviewers arrive

1. Confirm the Function App and its supporting Storage, Event Grid, and SQL
   resources are deployed and healthy. The Function App must use
   `REACT_MOCK_MODE=false` and be scoped to the disposable target resource
   group.
2. Confirm the Windows test VM has `REACT-Demo=True` and does not have
   `Critical-Infrastructure=True`.
3. If demonstrating policy bypass, confirm the separate Linux test VM has both
   `REACT-Demo=True` and `Critical-Infrastructure=True`.
4. Confirm both VMs are running and their original NSG associations are known.
   Never use a production or investigator-owned machine.
5. In PowerShell, load the Function App, resource group, and VM IDs using the
   approved local values. Do not paste Function keys, SAS URLs, or credentials
   into slides, chat, source files, or screenshots.

## Live walkthrough

The read-only preflight is quick; live acquisition time depends on VM memory
size, Run Command completion, and custody delivery. Allow up to the configured
status timeout for custody, and up to 90 minutes for the memory Function call.

### 1. Problem and architecture

> "REACT addresses the incident-response tradeoff between preserving volatile
> memory and limiting an attacker's ability to move laterally. The Azure
> Function App coordinates containment, memory acquisition, custody
> verification, and gated disk snapshots. The forensic enclave is separate
> from the target workload boundary."

Clarify that the demo uses real Azure infrastructure and a disposable test VM.
The PowerShell script calls the deployed Function endpoints directly; it does
not deploy infrastructure or invoke the Logic App workflow.

### 2. Read-only preflight

Run the preflight against the Windows demo VM:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $env:FUNC_APP_NAME `
  -FunctionAppResourceGroup $env:ENCLAVE_RG `
  -TargetVmId $env:WEB01_ID `
  -Scenario Standard `
  -PreflightOnly
```

> "Before it can take action, the orchestrator verifies the active Azure
> session, Function App health and live-mode setting, the target subscription
> and resource-group boundary, the custody Event Grid subscription, the VM's
> disposable-demo tag, and its running state. This check is read-only."

### 3. Standard containment and memory acquisition

Run the live standard scenario. Confirm containment, acquisition, and (if
approved) disk snapshots when prompted:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $env:FUNC_APP_NAME `
  -FunctionAppResourceGroup $env:ENCLAVE_RG `
  -TargetVmId $env:WEB01_ID `
  -Scenario Standard `
  -CaptureDiskSnapshots `
  -ConfirmLiveActions
```

> "The target remains powered on. The containment Function replaces its NIC
> NSG association with a deny-by-default isolation NSG and saves the previous
> associations in a local, secret-free recovery summary. After a second
> confirmation, the acquisition Function dispatches the OS-appropriate memory
> collector through Azure Run Command. The orchestrator waits for the
> Event Grid and custody path to verify the evidence before requesting disk
> snapshots."

Point reviewers to the reported containment outcome, evidence blob name,
custody SHA-256, disk snapshot count, and run-summary path. The script does not
print or save Function keys or SAS URLs.

### 4. Critical-infrastructure policy bypass (optional)

Use the separately tagged disposable Linux VM:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $env:FUNC_APP_NAME `
  -FunctionAppResourceGroup $env:ENCLAVE_RG `
  -TargetVmId $env:DB02_ID `
  -Scenario CriticalBypass `
  -CaptureDiskSnapshots `
  -ConfirmLiveActions
```

> "The VM carries the critical-infrastructure tag, so the containment Function
> reports `Bypassed` and does not change its NICs. The user must still confirm
> live memory acquisition. The custody gate remains in force before disk
> snapshots."

### 5. Restore the standard test VM

After reviewers have inspected the isolated VM, use the recovery summary
printed by the standard scenario:

```powershell
.\scripts\run-azure-demo.ps1 `
  -RestoreFrom "<run-summary-path>" `
  -ConfirmRestore
```

> "Restoration is a separate, explicit action. Before changing each NIC, the
> script verifies it still has this incident's isolation NSG. If another
> operator changed the NIC, restoration stops rather than overwriting that
> change."

Evidence blobs and disk snapshots are retained. The demo does not remove
immutable evidence, delete snapshots, or delete the forensic enclave; handle
retention and cleanup under the approved evidence policy.

## Reviewer Q&A

| Question | Suggested answer |
|---|---|
| Why not stop the VM? | Stopping or deallocating a VM destroys volatile memory. The standard flow isolates the network while leaving the test VM running. |
| What does the demo change? | The standard scenario changes the test VM's NIC NSG association and runs memory acquisition. Disk snapshots are an additional opt-in action. |
| How is evidence integrity checked? | The Blob-created event invokes the custody Function, which calculates a SHA-256 digest and records the result in the configured ledger path. The script waits for custody completion before requesting snapshots. |
| Does this create Azure resources? | This runner does not deploy infrastructure or VMs. It uses pre-deployed Azure services and can create an incident isolation NSG, evidence blobs, and optionally disk snapshots. Those resources may incur charges. |
| Does the script run the Logic App? | No. It calls the deployed Function endpoints directly for a controlled review. The Logic App workflow is a separate integration path. |
| How do you restore the VM? | Use the secret-free run summary with `-RestoreFrom`; the script validates the current NIC state and requires a typed confirmation before restoring the saved NSG associations. |
