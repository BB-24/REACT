# REACT Azure Integration Plan

## Goal and scope

Extend the completed offline REACT prototype with a small, safe Azure-backed
demo. The first cloud milestone should send **synthetic demo evidence** to
Azure Blob Storage, process its event, record chain-of-custody metadata, and
show telemetry. Network containment and evidence acquisition against real
machines remain simulated.

This is a plan only. No Azure resource should be created or changed until the
subscription, region, expected costs, security settings, and deployment
`what-if` are reviewed and the user explicitly approves deployment.

## Starting point

[`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) reports the offline
prototype complete: 129 passing tests, clean Ruff checks, a CLI and browser
dashboard, three scenarios, reset support, and offline safety checks. First
reproduce those results on the exact commit selected for cloud work.

Relevant integration surfaces:

- [`iac/main.bicep`](../iac/main.bicep) defines a resource-group-scoped
  evidence enclave with Storage, Key Vault, Event Grid, SQL Ledger, Application
  Insights, and a Linux Function App.
- [`src/functions/shared/clients.py`](../src/functions/shared/clients.py)
  currently switches all Azure clients together using `REACT_MOCK_MODE`.
  Disabling it can enable real compute and network clients too; do not use that
  switch to enable Storage alone.
- [`src/logic-apps/workflow.json`](../src/logic-apps/workflow.json) defines the
  workflow and [`iac/modules/logic-app.bicep`](../iac/modules/logic-app.bicep)
  defines a Logic App module. Verify whether the top-level Bicep invokes that
  module before expecting it to deploy.
- Treat Bicep as the source of truth. Verify whether
  [`iac/main.json`](../iac/main.json) is synchronized before using it.
- The main template currently uses EP1, has public network access settings and
  an Azure-services SQL firewall rule, and configures a 2,555-day retention
  period and legal hold. These are review items, not suitable assumptions for
  disposable demo data. The existing
  [`cost model`](./cost-model.md) may not reflect the deployed template's SKUs.

## First-milestone architecture

```text
Local REACT CLI / dashboard
    |
    | synthetic payload only
    v
Azure Function App
    | compute and network adapters remain mocked
    +--> demo Blob Storage
    +--> Event Grid --> Chain of Custody Function --> SQL Ledger
    +--> Application Insights

No live VM operations. Add Logic App only after this path is verified.
```

Keep the local mock-only demo available as the no-network fallback. Use a
dedicated demo subscription if possible, otherwise a dedicated resource group
containing only disposable demo resources.

## Step-by-step implementation

### Step 1 — Select the cloud-demo boundary

1. Decide which commit contains the completed prototype reported in
   [`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).
2. Review and commit the prototype changes before starting Azure integration.
3. Keep the first milestone limited to synthetic Blob upload, Event Grid
   delivery, custody metadata, and monitoring.
4. Explicitly exclude live VM containment, memory acquisition, disk snapshots,
   and target-subscription access.

**Done when:** The selected commit and milestone boundary are recorded. No
target-machine resource IDs or target permissions are needed for the planned
demo.

### Step 2 — Reproduce the offline baseline

From the repository root, run:

```powershell
pytest -q
ruff check .
python scripts/demo.py --check
python scripts/demo.py --scenario 1
python scripts/demo.py --scenario 2
python scripts/demo.py --scenario 3
python scripts/demo.py --reset
```

1. Record each command and its result.
2. Start the dashboard using the documented command in
   [`README.md`](../README.md); verify it is responsive, then stop it cleanly.
3. Verify that local checks and scenarios work without Azure credentials or
   network access.

**Done when:** All baseline checks pass on the selected commit and the offline
demo remains usable as a fallback.

### Step 3 — Validate the Functions package and infrastructure source

1. Confirm `src/functions/host.json`, dependency files, all four blueprint
   registrations, and required Function App settings are present.
2. Keep the Function App on the Python v2 programming model. The checked-in
   `src/functions/NetworkContainment/function.json` was V1 metadata alongside
   the V2 `function_app.py` and caused Core Tools to reject packaging. Remove
   legacy V1 metadata only when its required route is preserved by a registered
   V2 blueprint. The V2 app must continue to expose the expected
   `/api/NetworkContainment` endpoint.

   **Verified in this branch:** Removing the legacy
   `NetworkContainment/function.json` allowed Core Tools to pass Python model
   validation, and the V2 blueprint alias preserves the
   `/api/NetworkContainment` route. The stale comment describing the V1 host
   entrypoint was updated; the classic `main` helper remains for direct
   compatibility/tests.

3. Package and publish from `src/functions`, where `host.json` and
   `requirements.txt` are at the app root. For a structural/local package
   check, use a temporary output path:

   ```powershell
   Push-Location src\functions
   func pack --output "$env:TEMP\react-functions-package"
   Pop-Location
   ```

   This command validates the programming model and creates
   `functions.zip`. In this branch, the archive contained root-level
   `host.json`, `function_app.py`, all four blueprint modules, and no
   `function.json`. Do not deploy a Windows-built archive to the Linux Function
   App. This workspace uses Python 3.14 while the Bicep Function App targets
   Python 3.11; the local package was observed to contain Windows CPython 3.14
   native wheels, so this check proves package structure only, not Linux runtime
   compatibility.
4. For a local Linux-native dependency build, use
   `func pack --build-native-deps` only when Docker is available and the build
   environment uses the same Python version as the target Function App. Inspect
   the resulting archive for root-level `host.json`, `function_app.py`, all
   registered blueprint modules, `.python_packages`, and absence of legacy
   `function.json` files and development-only files. Keep package output outside
   the source tree.
5. For actual code deployment, use Core Tools remote build from the Functions
   project root after infrastructure exists and deployment has been separately
   approved:

   ```powershell
   Push-Location src\functions
   func azure functionapp publish <function-app-name> --build remote
   Pop-Location
   ```

   Remote build installs `requirements.txt` in the Azure Linux/runtime
   environment. Do not use `--publish-local-settings` for this prototype;
   configure reviewed app settings through the approved deployment/IaC path.
   The command publishes code and is not part of local validation. The installed
   Core Tools reported that it was outdated; use a current supported Core Tools
   release before any deployment.
6. Add or review `.funcignore` so local settings, tests, caches, and other
   development-only files are excluded from the deployment package.
7. Build the top-level Bicep and every module. For example:

   ```powershell
   az bicep build --file iac/main.bicep
   Get-ChildItem iac/modules/*.bicep | ForEach-Object {
       az bicep build --file $_.FullName
   }
   ```

8. Resolve compilation or linter errors. Confirm all required parameters,
   module references, role assignments, outputs, and resource dependencies.
9. Confirm the top-level Bicep includes or intentionally excludes the Logic App
   module. Do not rely on an outdated generated ARM template.
10. Trace the synthetic upload path through its Function handler, storage
   client, Event Grid event, custody handler, and optional SQL write.

**Done when:** Core Tools accepts the V2 project, the package layout and target
runtime are verified, the Function build/deployment method is documented, and
Bicep source validates. Do not treat a successful Windows package build as
proof that the archive can run on Linux.

### Step 4 — Add explicit hybrid adapter modes

1. Replace the single all-or-nothing `REACT_MOCK_MODE` choice for this path with
   explicit configuration for storage/ledger and compute/network adapters.
2. Keep compute and network in mock mode in every first-milestone cloud run.
3. Allow real Storage access only when explicitly configured for the demo
   account and container. Keep SQL mock mode until its integration is selected
   and tested.
4. Keep mock-only mode as the default for local runs and automated tests.
   Reject unknown or contradictory settings with a visible error.
5. Show which adapters are real or simulated in the protected health response,
   dashboard, and logs. Preserve the existing `SIMULATED` label for synthetic
   incident actions and data.
6. Add tests for mock-only and hybrid configuration, and verify that hybrid
   tests do not construct real compute/network clients or make unintended
   network calls.
7. Verify logs, UI, and responses never contain credentials, Function keys, or
   SAS bearer URLs.

**Done when:** Hybrid mode can use Azure Storage while compute/network remain
mocked, and invalid settings fail closed. Existing offline scenario tests still
pass.

### Step 5 — Choose the Azure target and review costs

1. Choose the demo subscription, tenant, region, and resource-group name.
   Prefer a subscription isolated from production and investigation workloads.
2. Confirm the signed-in identity and active subscription:

   ```powershell
   az account show --query "{name:name,id:id,tenantId:tenantId}" --output json
   ```

3. Check policy, provider registration, quota, and regional availability for
   the resources in the proposed deployment.
4. Estimate actual costs for Function hosting, Storage, Event Grid, SQL
   (if included), and Application Insights. Set a budget or alert before
   deployment.
5. Reconcile the current EP1 Function plan and SQL SKU with the demo workload.
   Evaluate Flex Consumption for an appropriate low-volume workload, including
   its required deployment configuration, or retain EP1 only with a documented
   reason.
6. Record resource names, region, SKUs, expected cost, access method, budget,
   and cleanup plan in the deployment review.

**Done when:** The subscription and region are confirmed, required capacity is
available, and expected costs are understood. Do not create the resource group
yet.

### Step 6 — Prepare a demo-specific Bicep configuration

1. Create a demo-specific parameter file such as
   `iac\parameters\demo.parameters.json`; keep any sensitive values out of the
   file and repository. Do not change production defaults implicitly.
2. Include only the first milestone's required resources: Function runtime
   storage, demo evidence Storage, Function App, managed identity, and
   Application Insights. Add Event Grid and SQL only when their end-to-end
   paths are included and tested.
3. Use synthetic fixtures only. Do not apply a legal hold, locked immutability,
   or multi-year retention to disposable demo evidence. Decide the shortest
   valid retention and safe cleanup behavior before deployment.
4. Review Storage, Key Vault, and SQL networking. Prefer private endpoints or
   restricted access. If public access is needed for the presentation, document
   and constrain the exception; remove the broad SQL Azure-services firewall
   rule from the demo configuration unless specifically justified.
5. Configure HTTPS-only access, TLS 1.2+, Linux Functions, diagnostics, and
   non-anonymous Function authentication.
6. Use managed identity with least privilege for the data path. Do not grant
   Network Contributor, VM write, disk snapshot, Run Command, or target
   subscription Reader permissions to the demo identity.
7. Keep storage keys and secrets out of source, parameter files, logs, and the
   browser. Use managed identity for Azure-hosted services and short-lived,
   narrowly scoped tokens only when required.
8. Add consistent demo ownership and cost tags to all resources.

**Done when:** The parameterized configuration contains only reviewed resources
and settings, has a documented cost estimate, and has no target-machine
permissions or irreversible demo-data retention.

### Step 7 — Validate the proposed deployment before approval

1. Run Bicep build and lint, then the repository's applicable IaC security
   checks.
2. Review the template for public endpoints, broad firewall rules, role
   assignment scopes, secret exposure, diagnostic settings, API versions, and
   retention/deletion behavior.
3. Create or identify the dedicated demo resource group only after a separate
   explicit approval to create it.
4. Generate a deployment preview:

   ```powershell
   az deployment group what-if `
       --resource-group <demo-resource-group> `
       --template-file iac/main.bicep `
       --parameters "@iac\parameters\demo.parameters.json"
   ```

5. Inspect every resource and change in the `what-if`. Resolve unexpected
   creates, updates, deletes, role grants, or networking changes.
6. Present the subscription, resource group, region, resource list, cost
   estimate, security exceptions, and `what-if` results for deployment
   approval. Stop here until the user explicitly approves provisioning.

**Done when:** A reviewer has approved the exact deployment preview. A `what-if`
is not permission to deploy.

### Step 8 — Provision the minimum Azure foundation

Only after Step 7 receives separate explicit deployment approval:

1. Deploy the reviewed Bicep configuration to the approved demo resource group.
   Do not deploy the template if its parameters or `what-if` changed.
2. Save deployment outputs securely. Treat Function keys, connection strings,
   and SAS URLs as secrets; do not copy them into the repository or
   presentation screenshots.
3. Deploy the Function App package using the approved method.
4. Confirm the Function App starts and its authenticated `/api/health` endpoint
   reports the expected real/simulated adapter modes.
5. Send a harmless health request and confirm the request and dependencies
   appear in Application Insights.
6. Confirm the Function App identity has only the required runtime and demo
   Storage roles. Verify it has no target VM/network control permissions.

**Done when:** Deployed resources match the approved preview, the Function App
is healthy, and monitoring works without exposing secrets.

### Step 9 — Verify a synthetic Blob upload

1. Use a unique incident identifier clearly marked as a demo/test.
2. Trigger the documented synthetic upload path with compute/network adapters
   still mocked.
3. Confirm the blob is in the expected private demo container and has metadata
   identifying it as synthetic.
4. Verify access from the intended identity; verify anonymous access is denied.
5. Confirm the demo dashboard or walkthrough shows the upload result without
   showing keys or signed URLs.
6. Check Application Insights for the successful request and ensure no
   credentials or SAS values appear in traces.

**Done when:** A synthetic upload can be repeated and inspected, and the local
mock-only path continues to work.

### Step 10 — Add Event Grid and custody verification

1. Deploy or enable the Event Grid subscription only after the standalone Blob
   upload is reliable.
2. Send another synthetic blob-created event and verify delivery to the
   authenticated Chain of Custody Function.
3. Test Event Grid validation, retries, duplicate delivery, failed delivery,
   and dead-letter behavior using synthetic data.
4. If SQL Ledger is in scope, configure the database identity and schema using
   [`iac/scripts/init-sql-ledger.sql`](../iac/scripts/init-sql-ledger.sql).
   Grant only required database permissions.
5. Verify the resulting custody row/hash and any ledger digest using the
   repository's supported verification path.

**Done when:** One synthetic upload can be traced through Blob Storage, Event
Grid, the custody handler, and SQL if enabled; failures are visible and safely
retryable.

### Step 11 — Add Logic App orchestration as a separate milestone

1. Keep this step out of the first Azure deployment unless Steps 1–10 are
   complete and verified.
2. Wire [`iac/modules/logic-app.bicep`](../iac/modules/logic-app.bicep) into the
   top-level Bicep or prepare a separately reviewed deployment.
3. Replace placeholder acquisition and analysis URLs only with authenticated
   demo endpoints that operate on synthetic data.
4. Review trigger exposure, managed identity audience, downstream
   authentication, run-history retention, retry count, and timeout behavior.
5. Add and test a guard that prevents calls to real network containment,
   acquisition, or disk-snapshot endpoints.
6. Run a synthetic incident and inspect Logic App run history, Function traces,
   storage output, and custody result.

**Done when:** A synthetic incident is orchestrated end to end and cannot
address a live target resource.

### Step 12 — Rehearse, observe, and clean up

1. Test invalid payloads, denied access, unavailable Storage/Event Grid/SQL,
   retry exhaustion, duplicate events, and Function restart.
2. Confirm alerts/budgets and Application Insights retention/sampling settings.
3. Rehearse from a clean checkout: local-only fallback first, then the
   Azure-backed synthetic scenario.
4. Verify every screen and log labels synthetic data and reveals which
   components are simulated versus Azure-connected.
5. Record a fallback demo and document startup, test, reset, troubleshooting,
   and cleanup commands.
6. Before cleanup, inspect retention and legal-hold configuration. Delete only
   disposable resources and data whose removal is permitted; do not assume a
   successful resource-group delete can remove immutable data.

**Done when:** Another team member can repeat the demo, explain its boundaries,
and clean up the approved disposable resources safely.

## Safety rules

- Never connect this prototype to a real target VM or accept arbitrary target
  resource IDs for cloud operations.
- Keep compute/network actions simulated throughout this milestone. Do not
  grant the demo identity Network Contributor, VM write, snapshot, Run Command,
  or target subscription Reader.
- Mark synthetic evidence in UI, API responses, logs, and blob metadata.
- Do not put credentials, Function keys, or SAS bearer URLs in source,
  screenshots, browser code, logs, or committed parameter files.
- Treat public networking, SQL firewall rules, RBAC, retention, legal holds,
  and deletion as explicit review items.
- Preserve and test the offline demo as the fallback.
- A deployment `what-if` is required but does not replace explicit deployment
  approval.

## Final acceptance checklist

- [ ] Reported 129-test / Ruff baseline reproduced on a known commit.
- [ ] Offline CLI/dashboard scenarios and reset continue to work.
- [ ] Hybrid mode uses real demo Storage only; compute/network remain mocked.
- [ ] Bicep source, modules, parameter file, and generated artifacts are
  reconciled and validated.
- [ ] Subscription, region, SKUs, cost estimate, security review, and cleanup
  plan are documented.
- [ ] Deployment `what-if` was reviewed and provisioning separately approved.
- [ ] Synthetic Blob upload, Event Grid delivery, custody result, and telemetry
  are verified end to end.
- [ ] Logic App is either explicitly deferred or separately validated without
  live target-machine access.
- [ ] Presenter can distinguish Azure-connected services from simulation.
