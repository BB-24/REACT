# REACT Live Azure Demo: Presenter Walkthrough

This guide covers the prerequisites, safe startup, live execution, recovery,
and project-file tour for presenting the REACT prototype. It describes the
live Azure runner, [`scripts/run-azure-demo.ps1`](../scripts/run-azure-demo.ps1),
not the offline simulator.

## 1. What this demo proves

REACT demonstrates an incident-response sequence that aims to preserve
volatile memory while limiting the target VM's network activity:

1. Validate the incident target and its Azure scope.
2. Isolate a disposable, non-critical test VM without stopping it.
3. Use Azure Managed Run Command to acquire memory and send the resulting
   evidence to the forensic enclave.
4. Wait for Event Grid and the chain-of-custody Function to verify the evidence
   and record its digest.
5. Optionally request disk snapshots, but only after memory custody is
   reported complete.
6. Restore the test NICs' original NSG associations after the presentation.

This is a live demonstration: containment can interrupt network connectivity,
memory images can contain secrets or personal data, and snapshots/storage can
incur charges. Use only a specifically approved, disposable demo VM. Never use
a production machine, an investigator's workstation, or real case evidence.

### The runner's boundary

The runner calls deployed Function endpoints directly. It does **not** deploy
infrastructure, create or tag VMs, invoke the Logic App workflow, run the
forensic analyzer, or generate a final report. The Logic App and offline
simulator are separate project paths. The runner does not delete the evidence,
snapshots, or isolation NSG after the demo.

## 2. Prerequisites before demo day

### A. Workstation and operator access

- Windows PowerShell 5.1 or PowerShell 7, with the repo checked out and the
  working directory set to the repository root.
- Azure CLI installed and available as `az`.
- An authenticated Azure CLI session in the tenant containing the Function
  App and target resources.
- The signed-in operator can:
  - Read the Function App and its app settings.
  - List the Function App host keys (the runner uses the default key in
    memory).
  - List Event Grid system topics and subscriptions in the configured
    forensic resource group.
  - Read the target VM, its power state, NICs, private IP, tags, and current
    NSG associations.
  - Update target NIC NSG associations if using the runner's restore command.
- The Function endpoint must be reachable over HTTPS from the presenter
  workstation. If the app is private-network-only, connect to the approved
  network and verify private DNS first.

Use the narrowest approved permissions. Listing Function keys is a sensitive
operation; do not use a shared account or expose the retrieved key. The runner
does not print or save it, but it is still used in Function request URLs.

### B. Already-deployed Azure services

The live runner requires the following to exist and be configured before it
starts:

- A running Linux Function App with the REACT Functions code already
  published, HTTPS-only access, and `REACT_MOCK_MODE=false`.
- Function App settings whose target subscription and resource group exactly
  match the target VM's resource ID:
  `AZURE_SUBSCRIPTION_ID` and `TARGET_RESOURCE_GROUP`.
- Function App settings for the forensic destination:
  `FORENSIC_SUBSCRIPTION_ID` and `FORENSIC_RESOURCE_GROUP`.
- Evidence Blob Storage, the SQL custody ledger, Key Vault if used for SAS
  signing/tool secrets, and the supporting networking/configuration required
  by the Function App.
- A **Succeeded** Event Grid system-topic event subscription in the configured
  forensic resource group, with an endpoint on this Function App host at
  `/api/custody` or `/api/ChainOfCustody`. The Bicep parameter
  `deployEventGridSubscription` defaults to `false`; publishing the Function
  code alone does not prove that the custody subscription exists.
- Deployed Functions exposing the routes used by the runner:
  `/api/health`, `/api/NetworkContainment`, `/api/MemoryAcquisition`,
  `/api/status`, and, if snapshots are requested,
  `/api/DiskSnapshotAcquisition`.

The Function App's managed identity—not the presenter's CLI identity—performs
the Azure-side containment and acquisition operations. Confirm that deployment
and post-deployment RBAC setup grant that identity the required rights in the
target workload and forensic scopes. The Bicep output
`postDeploymentPrincipal` calls out target-side Network Contributor, Reader,
disk-snapshot permissions, and a contained SQL user. Storage, Key Vault, and
queue roles are also assigned/configured by the enclave template. Validate
these permissions against the actual deployed resources; do not grant broad
subscription Owner or Contributor access just to make a demo pass.

### C. Existing disposable target VM

Prepare the VM before the presentation; the runner will not create or tag it.

- Use a running, disposable VM in the exact configured target subscription and
  resource group.
- Tag it `REACT-Demo=true`.
- For **Standard**, make sure it does not have
  `Critical-Infrastructure=true`.
- For **CriticalBypass**, use a separate disposable test VM tagged both
  `REACT-Demo=true` and `Critical-Infrastructure=true`. Do not add a
  critical-infrastructure tag to a real system merely to force this demo path.
- Verify that the VM has an attached NIC, a usable private IP, and known
  original NSG associations. A running VM is required for memory acquisition.
- Check that the OS and acquisition tool path (Windows/WinPmem or Linux/AVML)
  are supported and available through the deployed Functions' configured
  evidence/tool storage.
- Agree in advance who is authorized to approve isolation and acquisition,
  and how to handle any sensitive evidence produced.

### D. Time, cost, and evidence handling

- Run the read-only preflight well before the presentation, not for the first
  time in front of reviewers.
- Memory acquisition can take a long time. The Function call allows up to
  5,400 seconds (90 minutes); custody polling defaults to 30 minutes and can
  be configured from 1 to 180 minutes.
- Disk snapshots are optional and add resources, storage consumption, and
  potential cross-subscription charges. Leave them out of a time-limited
  presentation unless they are a specific review objective.
- Evidence is real. Agree where the recovery summary and evidence metadata
  may be stored, who may see the evidence, and which retention/legal-hold
  policies apply. The runner never deletes immutable evidence or snapshots.
- Make the offline simulator or a prepared recording/log available as a
  fallback. It is synthetic and is not evidence that the live Azure path ran.

## 3. Presenter setup in PowerShell

Open PowerShell at the repository root. Set local, non-secret values for the
deployed resources; use the actual values supplied by the environment owner:

```powershell
$functionAppName = "<deployed-function-app-name>"
$functionAppResourceGroup = "<function-app-resource-group>"
$functionAppSubscriptionId = "<function-app-subscription-guid>"
$targetVmId = "/subscriptions/<target-subscription-guid>/resourceGroups/<target-resource-group>/providers/Microsoft.Compute/virtualMachines/<demo-vm-name>"
```

Sign in and select the Function App subscription. The target VM can be in a
different subscription; its full resource ID is passed to the runner:

```powershell
az login
az account set --subscription $functionAppSubscriptionId
az account show --output table
az vm show --ids $targetVmId --query "{id:id,tags:tags,nics:networkProfile.networkInterfaces[].id}" --output json
az vm get-instance-view --ids $targetVmId --query "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus | [0]" --output tsv
```

If you prefer, obtain the full target VM ID with Azure CLI:

```powershell
$targetVmId = az vm show `
  --subscription "<target-subscription-guid>" `
  --resource-group "<target-resource-group>" `
  --name "<demo-vm-name>" `
  --query id `
  --output tsv
```

Do not put Function keys, SAS URLs, credentials, or real evidence in shell
history, slides, source files, screenshots, or chat. The script retrieves its
Function key itself after the read-only Azure checks.

## 4. Run the preflight first

Use the exact Function App subscription explicitly so a stale CLI default
cannot point the script at the wrong Function App:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $functionAppName `
  -FunctionAppResourceGroup $functionAppResourceGroup `
  -FunctionAppSubscriptionId $functionAppSubscriptionId `
  -TargetVmId $targetVmId `
  -Scenario Standard `
  -PreflightOnly
```

Preflight checks the Azure CLI session, Function App state and HTTPS setting,
the app's live-mode and resource-scope settings, the Event Grid custody
subscription, target tags and scenario, VM power state, NIC/IP information,
Function health, and ability to obtain a Function key. It performs read
operations and a health GET only. It does not contain the VM, collect memory,
create snapshots, or change resources.

Do not proceed unless the preflight succeeds and a reviewer can identify the
target as disposable. A preflight failure is a stop signal, not something to
work around by removing a safety check or widening permissions.

## 5. Standard live walkthrough

For a presentation, begin without disk snapshots. Add the optional snapshot
switch only if that part has been approved and there is enough time:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $functionAppName `
  -FunctionAppResourceGroup $functionAppResourceGroup `
  -FunctionAppSubscriptionId $functionAppSubscriptionId `
  -TargetVmId $targetVmId `
  -Scenario Standard `
  -ConfirmLiveActions
```

`-ConfirmLiveActions` is required to enable the live path, but it does not skip
the script's typed confirmations. The prompts are intentional:

1. The script asks for `RUN <IncidentId>`. Confirming calls the containment
   Function. The Function creates/uses an incident isolation NSG and replaces
   the NSG association on the target VM's NICs. The VM stays running.
2. Before the live calls, the script writes an initial recovery summary in the
   presenter's temporary directory (normally `$env:TEMP`). After containment,
   it updates that summary with the incident NSG and previous NSG associations.
   It does not include the Function key or SAS URLs.
3. The script asks for `ACQUIRE <IncidentId>`. Confirming calls
   `MemoryAcquisition`. If this second prompt is declined, **containment may
   already have happened**; keep the recovery summary and restore only after
   the authorized reviewer says it is safe.
4. The memory Function dispatches the OS-specific acquisition through Azure
   Managed Run Command. The host streams the memory image to evidence storage;
   this is a real acquisition, not mock data.
5. The runner polls `/api/status` every 15 seconds. It proceeds only when the
   custody result is `Completed`; a failure or timeout prevents the optional
   snapshot call.
6. The runner displays a concise result and writes the secret-free run summary.
   Preserve the summary until restoration has been verified.

To opt into disk snapshots, add `-CaptureDiskSnapshots`. After custody
completes, the runner requests a separate typed confirmation,
`SNAPSHOT <IncidentId>`, calls `DiskSnapshotAcquisition`, and checks that the
Function reports a satisfied memory gate. Snapshots are real Azure resources;
they are not cleaned up by this script.

### Useful runner parameters

| Parameter | Default / purpose |
|---|---|
| `-FunctionAppSubscriptionId` | Defaults to the active Azure CLI subscription. Pass it explicitly for repeatable demos, especially when target and enclave subscriptions differ. |
| `-Scenario` | `Standard` by default; `CriticalBypass` requires the critical tag on a separate disposable VM. |
| `-IncidentId` | Generated as `INC-DEMO-<UTC timestamp>` if omitted. A supplied value must be 1-63 letters, digits, underscores, or hyphens and start with a letter or digit. |
| `-IncidentIpAddress` | Optional override; by default the runner obtains the primary NIC's private IP. |
| `-IncidentSeverity` | `High` by default; accepted values are `High` and `Critical`. |
| `-StatusTimeoutMinutes` | 30 minutes by default; valid range is 1-180 minutes. |
| `-PreflightOnly` | Performs checks and exits before containment or evidence collection. |
| `-ConfirmLiveActions` | Required to enter the live path; does not skip the typed `RUN`, `ACQUIRE`, or optional `SNAPSHOT` prompts. |
| `-CaptureDiskSnapshots` | Requests snapshots after custody is complete and after the separate typed confirmation. |
| `-RestoreFrom` | Selects the separate network-restoration parameter set and reads the saved run summary. |
| `-ConfirmRestore` | Required alongside `-RestoreFrom`; a typed `RESTORE <IncidentId>` is still required interactively. |

### What reviewers should observe

- The target VM remains powered on.
- Standard containment reports `Contained` and returns an isolation NSG name.
- The Function reports the acquired platform and evidence blob name.
- Custody status reaches `Completed` and shows a SHA-256 digest.
- If snapshots were approved, the result reports the snapshot count and
  satisfied memory gate.
- The local summary path is shown for recovery.

The runner does not print the Function key or SAS URLs. Do not expose the
summary indiscriminately: while it contains no credentials, it includes
resource IDs and incident/evidence metadata.

## 6. Optional critical-infrastructure bypass scenario

Use only a separate, disposable VM tagged
`REACT-Demo=true` and `Critical-Infrastructure=true`:

```powershell
.\scripts\run-azure-demo.ps1 `
  -FunctionAppName $functionAppName `
  -FunctionAppResourceGroup $functionAppResourceGroup `
  -FunctionAppSubscriptionId $functionAppSubscriptionId `
  -TargetVmId "<full-resource-id-of-the-disposable-bypass-test-vm>" `
  -Scenario CriticalBypass `
  -ConfirmLiveActions
```

The runner calls `NetworkContainment` and requires `Bypassed`. It then
continues only after the separate acquisition confirmation. This scenario
demonstrates the policy decision; it does not bypass the data-sensitivity,
authorization, or evidence-custody safeguards.

## 7. Restore the network after the demo

Keep the recovery summary path printed by the run. Restore only when the
authorized operator has approved reconnecting the test VM:

```powershell
.\scripts\run-azure-demo.ps1 `
  -RestoreFrom "<full-path-to-react-demo-summary.json>" `
  -ConfirmRestore
```

The runner reads the summary, confirms that every NIC being restored still
uses the incident's isolation NSG, asks for `RESTORE <IncidentId>`, restores
the saved NSG IDs (including a previously unassociated NIC), and verifies the
result. If another operator changed a NIC after containment, the runner stops
instead of overwriting that newer state. The incident isolation NSG remains
for review; evidence and snapshots remain subject to the configured retention
policy.

If anything fails after containment, assume the VM is still isolated. Do not
delete the summary or isolation NSG. Inspect the NIC and Function state, then
use the guarded restore command or the approved manual recovery runbook:
[`restoration-runbook.md`](./restoration-runbook.md).

## 8. Presentation talk track

### Opening

> "REACT addresses a responder's dilemma: stopping a compromised VM can erase
> volatile memory, but leaving it connected can permit further activity. This
> prototype demonstrates network containment while keeping the disposable
> target powered on, followed by memory collection and evidence-custody
> verification."

### Before preflight

> "This is the live Azure path. The resources are pre-deployed; the runner
> doesn't create infrastructure or VMs. We use a VM explicitly tagged as
> disposable, and the runner checks that target before it can call containment."

### At containment and acquisition

> "The first typed confirmation applies the isolation NSG. We then separately
> confirm memory acquisition. That separation is deliberate: network changes
> and forensic collection are distinct live actions, and the recovery summary
> is available if the run needs to stop."

### At custody and wrap-up

> "A successful upload is not yet a completed custody record. The runner waits
> for the BlobCreated event to reach the custody Function, which independently
> hashes the evidence and records it in the ledger. Disk snapshots are
> optional and stay behind that custody gate. Finally, we restore the original
> NSG association and retain evidence according to policy."

### State the integration boundary

> "The project also includes a Logic App definition, report/analysis
> components, tests, and an offline simulator. This particular live presenter
> script calls the Functions directly; it does not claim to execute the Logic
> App end to end."

## 9. Project files and folders: presentation tour

The repository has two related but distinct demonstration paths:

- **Live Azure path:** `scripts/run-azure-demo.ps1` calls pre-deployed Azure
  Functions and operates on an existing, disposable VM.
- **Offline simulator:** `scripts/demo.py` and `src/demo/` run synthetic
  scenarios against in-memory Azure mocks. It is useful for tests and as a
  no-Azure fallback, but it is not the live demonstration.

### Root and developer tooling

| Path | Purpose |
|---|---|
| `README.md` | Project overview, safety boundary, quick start, and links to the live and offline demos. |
| `demo.md` | Detailed live deployment/demo runbook. Review its environment-specific resource assumptions before relying on them. |
| `IMPLEMENTATION_STATUS.md` | Implementation and test status record; it primarily describes the offline prototype and should not be presented as proof of a live Azure run. |
| `pyproject.toml` | Python project, test, and Ruff configuration. |
| `.gitignore` | Excludes local settings, virtual environments, caches, coverage, and local parameter files; explicitly permits the two tracked demo launchers. |
| `.gitleaksignore` | Narrow exceptions for secret-scanning paths/patterns. |
| `.pre-commit-config.yaml` | Pre-commit checks for contributors. |
| `.github/CODEOWNERS` | Default code ownership assignments. |
| `.github/pull_request_template.md` | Pull request description and review checklist. |
| `.github/workflows/ci-pipeline.yaml` | CI checks for changed project areas, such as tests, lint, IaC, and security. |
| `.github/workflows/integration-tests.yml` | Separate integration-test workflow. |
| `.vscode/extensions.json` | Recommended VS Code extensions. |
| `.vscode/launch.json` | VS Code debug launch configurations. |
| `.vscode/settings.json` | Workspace editor settings. |
| `.vscode/tasks.json` | Reusable VS Code tasks. |

### `scripts/`

| Path | Purpose |
|---|---|
| `scripts/run-azure-demo.ps1` | Live presenter runner: read-only preflight, typed live-action gates, containment, memory acquisition, custody polling, optional snapshots, summary, and guarded NSG restore. |
| `scripts/demo.py` | Offline CLI/menu launcher; it does not invoke Azure or acquire genuine evidence. |

### `src/functions/`: Azure Functions implementation

`function_app.py` registers the HTTP Function blueprints. Each feature folder
contains a Function handler; the Functions use the shared client/config
modules to select mock or real Azure clients.

| Path | Purpose |
|---|---|
| `src/functions/function_app.py` | Azure Functions v2 app root; registers NetworkContainment, MemoryAcquisition, DiskSnapshot, and ChainOfCustody, plus health and mock-only routes. |
| `src/functions/host.json` | Azure Functions host/runtime configuration. |
| `src/functions/requirements.txt` | Python runtime dependencies for the Function App. |
| `src/functions/.funcignore` | Excludes local/development files from a Functions publish package. |
| `src/functions/local.settings.sample.json` | Example local Function settings; it is not the deployed app configuration and must not contain real secrets. |
| `src/functions/conftest.py` | Shared fixtures for the Function-level tests. |
| `src/functions/NetworkContainment/__init__.py` | Validates incident scope and tags; creates/attaches an isolation NSG or returns the critical-infrastructure bypass response. |
| `src/functions/NetworkContainment/requirements.txt` | Network Function-specific dependency declaration. |
| `src/functions/MemoryAcquisition/__init__.py` | Builds and dispatches memory collection using Azure Run Command, and exposes status endpoints. |
| `src/functions/DiskSnapshot/__init__.py` | Captures/copies disk snapshots and enforces the memory-custody gate. |
| `src/functions/ChainOfCustody/__init__.py` | Handles BlobCreated events, independently hashes evidence, checks witness metadata, and records custody. |
| `src/functions/ReportGenerator/__init__.py` | Empty placeholder for the separate report-generator package; it is not registered by the current Function App root or invoked by this runner. |
| `src/functions/ReportGenerator/report_template.html` | HTML report template artifact; the live runner does not render or publish it. |
| `src/functions/shared/__init__.py` | Shared package exports. |
| `src/functions/shared/config.py` | Reads and validates Function App settings. |
| `src/functions/shared/clients.py` | Central seam choosing mock clients or real Azure SDK clients. |
| `src/functions/shared/ledger.py` | Azure SQL custody-ledger reads/writes. |
| `src/functions/shared/sas.py` | SAS creation and safe token-related helpers for evidence/tool access. |
| `src/functions/shared/mocks/__init__.py` | Mock client exports and mock support. |
| `src/functions/shared/mocks/_world.py` | In-memory simulated Azure estate and event/state model. |
| `src/functions/shared/mocks/_compute.py` | Simulates VM/run-command/disk behavior. |
| `src/functions/shared/mocks/_network.py` | Simulates NSGs, NIC associations, and containment. |
| `src/functions/shared/mocks/_storage.py` | Simulates blobs, containers, and storage events. |
| `src/functions/shared/mocks/_sql.py` | Simulates SQL ledger behavior. |
| `src/functions/shared/mocks/_keyvault.py` | Simulates Key Vault operations. |
| `src/functions/tests/test_disk_snapshot.py` | Tests snapshot acquisition and memory-gate behavior. |
| `src/functions/tests/test_memory_acquisition.py` | Tests acquisition, response, and custody handoff. |
| `src/functions/tests/test_sas.py` | Tests SAS behavior. |
| `src/functions/tests/test_worm_storage.py` | Tests immutable/WORM storage behaviors. |

The checked-in `local.settings.json` is intentionally ignored; use the sample
as a template for local-only mock work. The live runner reads deployed Azure
configuration and does not use local Function settings.

### `src/scripts/`: target-side memory acquisition scripts

| Path | Purpose |
|---|---|
| `src/scripts/Acquire-Memory.ps1` | Windows acquisition helper used by the live memory path; streams memory evidence rather than writing a full image to the VM disk. |
| `src/scripts/acquire-memory.sh` | Linux acquisition helper for supported Linux acquisition tools. |
| `src/scripts/README.md` | Explains tool retrieval, streaming, witness hashes, and operational constraints. |

### `src/logic-apps/`: workflow definitions

| Path | Purpose |
|---|---|
| `src/logic-apps/workflow.json` | Logic App workflow definition for incident orchestration. It is not invoked by `run-azure-demo.ps1`. |
| `src/logic-apps/incident-response-playbook.json` | Incident-response playbook/workflow artifact. |
| `src/logic-apps/README.md` | Workflow test and integration instructions. |

### `src/demo/`: offline presentation experience

| Path | Purpose |
|---|---|
| `src/demo/__init__.py` | Exposes the offline orchestrator and scenario helpers. |
| `src/demo/__main__.py` | Package entry point for the offline demo. |
| `src/demo/orchestrator.py` | Runs synthetic scenarios through the mock pipeline and returns presentation summaries. |
| `src/demo/server.py` | Hosts the local interactive browser dashboard. |

### `src/containers/forensic-analyzer/`

| Path | Purpose |
|---|---|
| `src/containers/forensic-analyzer/Dockerfile` | Builds the forensic analyzer container image. |
| `src/containers/forensic-analyzer/entrypoint.sh` | Starts the analyzer's processing entry point. |
| `src/containers/forensic-analyzer/verify-local.sh` | Local verification helper for the analyzer image/flow. |

This analyzer is a separate pipeline component and is not called by the live
PowerShell demo runner.

### `iac/`: infrastructure as code

| Path | Purpose |
|---|---|
| `iac/main.bicep` | Main forensic-enclave resource-group template, including Function App settings, storage, Event Grid, SQL, and RBAC. |
| `iac/main.json` | Generated ARM JSON template corresponding to Bicep; Bicep is the maintainable source. |
| `iac/main.mg.bicep` | Management-group-scope entry point for multi-subscription/resource-group setup. |
| `iac/modules/containment-function.bicep` | Reusable Function App module. |
| `iac/modules/logic-app.bicep` | Reusable Logic App module. |
| `iac/modules/rbac.bicep` | Target-scope network role assignment module. |
| `iac/modules/resource-group.bicep` | Single resource-group creation module. |
| `iac/modules/resource-groups.bicep` | Multi-resource-group orchestration module. |
| `iac/parameters/multi-subscription-demo.parameters.example.json` | Example non-secret parameters for multi-subscription deployment. |
| `iac/scripts/init-sql-ledger.sql` | SQL schema/setup for the evidence ledger and Function identity. |

The live demo runner requires these resources to have already been deployed and
configured. It does not run Bicep or deploy any of these files.

### `docs/`: architecture, contracts, operations, and presentation

| Path | Purpose |
|---|---|
| `docs/demo-presenter-script.md` | This live demo setup, presentation, recovery, and repository-tour guide. |
| `docs/demo-architecture.md` | Architecture of the offline mock pipeline and its safety boundary. |
| `docs/mid-sem prototype.md` | Mid-semester prototype implementation plan. |
| `docs/azure-integration-plan.md` | Staged plan for Azure integration; planning documentation, not the live runner. |
| `docs/adr-001-asynchronous-acquisition-architecture.md` | Decision record explaining asynchronous acquisition architecture. |
| `docs/orchestration.md` | Incident workflow/orchestration overview. |
| `docs/integration-openapi.json` | Machine-readable API and integration contract. |
| `docs/payload-contract.json` | Incident payload schema and required fields. |
| `docs/onboarding-guide.md` | Integration guidance for acquisition and analysis participants. |
| `docs/multi-subscription-deployment.md` | Multi-subscription deployment design and steps. |
| `docs/security-baseline.md` | Security controls and target baseline. |
| `docs/disaster-recovery.md` | Recovery and resilience guidance. |
| `docs/restoration-runbook.md` | Network restoration procedure and safety checks. |
| `docs/cost-model.md` | Cost drivers and estimation guidance; check assumptions against deployed SKUs. |
| `docs/testing-guide.md` | Test and verification instructions. |
| `docs/p1-p2-postman-evidence.md` | Postman procedure and evidence export for the P1-P2 workflow. |
| `docs/demo-fallback-log.md` | Captured offline demo output for presentation fallback. |

### `tests/`: verification and integration evidence

| Path | Purpose |
|---|---|
| `tests/conftest.py` | Shared top-level test fixtures. |
| `tests/test_demo_scenarios.py` | Tests offline demo scenarios and safety behavior. |
| `tests/test_network_containment.py` | Tests containment and policy behavior. |
| `tests/integration/__init__.py` | Integration test package marker. |
| `tests/integration/contracts/__init__.py` | Contract test package marker. |
| `tests/integration/contracts/test_openapi_integration_contract.py` | Checks API implementation against OpenAPI contract. |
| `tests/integration/contracts/test_payload_contracts.py` | Checks payload schemas and validation. |
| `tests/integration/e2e/__init__.py` | End-to-end test package marker. |
| `tests/integration/e2e/test_e2e_pipeline.py` | Exercises the composed pipeline using test fixtures/mocks. |
| `tests/integration/p1p2/__init__.py` | P1-P2 test package marker. |
| `tests/integration/p1p2/test_p1_p2_orchestration.py` | Tests containment-to-acquisition integration. |
| `tests/integration/p1p3/__init__.py` | P1-P3 test package marker. |
| `tests/integration/p1p3/test_p1_p3_reporting.py` | Tests orchestration/reporting integration. |
| `tests/integration/p2p3/__init__.py` | P2-P3 test package marker. |
| `tests/integration/p2p3/test_p2_p3_handoff.py` | Tests acquisition-to-analysis handoff. |
| `tests/postman/REACT-P1-P2-Containment.postman_collection.json` | Postman collection for the controlled P1-P2 flow. |
| `tests/postman/REACT-P1-P2-Demo.postman_environment.json` | Postman environment template for that collection. |
| `tests/unit/__init__.py` | Unit test package marker. |
| `tests/unit/test_forensic_analyzer_entrypoint.py` | Tests analyzer startup/entry point. |
| `tests/unit/test_person1_orchestration.py` | Tests Person 1 orchestration behavior. |
| `tests/unit/test_person2_acquisition_ledger.py` | Tests acquisition/ledger contract. |
| `tests/unit/test_person2_worm_storage.py` | Tests immutable evidence storage behaviors. |
| `tests/unit/test_person3_analysis_reporting.py` | Tests analysis and report integration. |

These automated tests mainly verify code/contracts and the mock-based pipeline;
passing tests do not, on their own, prove that the deployed Azure resources
are healthy or that a live acquisition succeeded.

### `sample-evidence/`

| Path | Purpose |
|---|---|
| `sample-evidence/README.md` | Describes the synthetic sample logs. |
| `sample-evidence/auth.log` | Synthetic authentication log fixture for analysis. |
| `sample-evidence/syslog.log` | Synthetic system log fixture for analysis. |

These fixtures are not real incident evidence and are used for local analyzer
demonstrations/tests, not as the target VM's acquired memory.

### Generated or local-only items

Folders such as `.git/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/`,
`.venv/`, `src/functions/.python_packages/`, and local
`src/functions/local.settings.json` are repository metadata, test/build
artifacts, environments, installed packages, or local configuration. They are
not part of the reviewer-facing demo deliverable. The actual tracked source
inventory is shown above.

## 10. Final checklist for tomorrow

- [ ] Function App is running, live mode is false for mock mode, and all
      required Functions are published.
- [ ] The forensic app settings point to the intended enclave and the target
      settings match the chosen test VM's subscription/resource group.
- [ ] Event Grid custody subscription is `Succeeded` and points to this
      Function App's custody route.
- [ ] Target VM is running, disposable, tagged correctly, and has known
      original NIC NSGs.
- [ ] Operator and Function managed identity permissions have been tested.
- [ ] `-PreflightOnly` passes for the exact target and scenario.
- [ ] Reviewers know that standard containment changes NIC NSG associations
      and that memory data is real/sensitive.
- [ ] Recovery summary path, restore operator, evidence handling, and cost
      owner are agreed.
- [ ] Offline simulator/recorded output is ready as a clearly labeled
      synthetic fallback.
- [ ] After review, the original NIC associations are restored and verified.
