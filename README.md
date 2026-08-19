# REACT — Rapid Evidence Acquisition & Containment Toolkit

An Azure-native digital-forensics and incident-response platform. When Sentinel
raises an incident, REACT isolates the affected VM, captures its volatile memory
without ever writing to the compromised disk, snapshots its disks into a
tamper-proof enclave, and records a cryptographically verifiable chain of
custody for every artifact.

**The whole pipeline runs today without an Azure subscription.** Mock mode
simulates the estate end to end — see [Running in mock mode](#running-in-mock-mode).

## The response pipeline

| # | Endpoint | Function | What it does | Requirements |
|---|---|---|---|---|
| 1 | `POST /api/contain` | `NetworkContainment` | Builds a deny-by-default isolation NSG and swaps it onto every NIC. Isolates, never deallocates — stopping the VM destroys the memory. | SOP 2 Phase 1 |
| 2 | `POST /api/acquire` | `MemoryAcquisition` | Generates a bootstrap script, ships it via Run Command, streams RAM to the enclave. | REQ‑3.3.1 – 3.3.4 |
| 3 | `POST /api/snapshot` | `DiskSnapshot` | Snapshots every managed disk and copies each across the subscription boundary. | REQ‑3.4.1 – 3.4.3 |
| 4 | `POST /api/custody` | `ChainOfCustody` | Event Grid webhook. Hashes each arriving blob and appends a ledger row. | REQ‑3.5.1 – 3.5.3 |

Steps 1–3 are driven in order by the Logic App. Step 4 is called by nobody —
Event Grid invokes it whenever a blob lands in the enclave container.

## Design decisions worth knowing

**Memory never touches the target's disk.** Writing a multi-gigabyte image to
the compromised host overwrites unallocated space that may itself be evidence,
hands an attacker with an active session a copy of the artifact being collected,
and often will not fit. The acquisition scripts slice the tool's stdout into
blocks and upload each with the Azure Blob `Put Block` API — the only approach
that works, since AzCopy cannot read from stdin, `Put Blob` needs a
`Content-Length` that is unknowable mid-stream, and Blob Storage rejects chunked
transfer-encoding. See [`src/scripts/README.md`](src/scripts/README.md).

**Every artifact is hashed twice.** The acquiring host folds a SHA‑256 over the
stream in flight and stamps that "witness hash" into blob metadata.
`ChainOfCustody` independently hashes the stored blob. A mismatch means the
bytes changed between the target and the enclave.

**Memory before disks.** Snapshotting induces I/O and page-cache pressure on the
target, perturbing exactly the volatile state Phase 2 exists to preserve. Disk
snapshotting is gated on a memory-image custody row actually existing in the
ledger — not on the Logic App's say-so.

**The enclave is a different subscription.** An attacker holding Contributor on
the compromised subscription can delete the source disks and the source
snapshots. The enclave copy is outside their RBAC scope entirely (REQ‑3.4.3).

**No long-lived secrets.** SAS tokens are user-delegation by default, signed
with a key obtained over AAD via the Function App's managed identity — so no
storage account key needs to exist. SQL uses `ActiveDirectoryMsi`, so no
password exists either.

## Repository layout

```
iac/
  main.bicep                    Enclave: storage, Key Vault, Event Grid, SQL, Functions
  scripts/init-sql-ledger.sql   Append-only ledger table, view, verification proc
src/
  functions/
    NetworkContainment/         Phase 1 — isolation NSG
    MemoryAcquisition/          Phase 2 — Run Command orchestration
    DiskSnapshot/               Phase 2b — snapshot + cross-subscription copy
    ChainOfCustody/             Phase 3 — Event Grid webhook, hashing, ledger
    MockControl/                Mock-mode only: drive and inspect the simulation
    ReportGenerator/            Person 3 — PDF reporting
    shared/
      clients.py                THE seam: mock vs. real Azure, one setting
      sas.py                    Write-only and read-only SAS minting
      ledger.py                 Append-only custody writes
      config.py                 Application settings
      mocks/                    The simulated Azure estate
  scripts/
    Acquire-Memory.ps1          Windows / WinPmem
    acquire-memory.sh           Linux / AVML, LiME, /proc/kcore
  logic-apps/                   Person 1 — Sentinel playbook
  containers/                   Person 3 — analysis container
```

## Running in mock mode

Mock mode replaces every Azure client with a simulated one. Two VMs, their
disks and NICs, an immutable evidence container under legal hold, a tool
repository, a Key Vault and an append-only ledger all exist in memory. The Run
Command simulation performs the *effect* the acquisition script would have —
it synthesises an image, uploads it through the write-only SAS, and raises a
`BlobCreated` event — so everything downstream of acquisition runs for real.

```bash
cd src/functions
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
cp local.settings.sample.json local.settings.json   # REACT_MOCK_MODE is already true
func start
```

Then drive the pipeline:

```bash
BASE=http://localhost:7071/api
INC='{"IncidentId":"INC-2026-0042","TargetVM":"/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-victims/providers/Microsoft.Compute/virtualMachines/web-01"}'

curl -s -X POST $BASE/contain  -d "$INC"   # isolate
curl -s -X POST $BASE/acquire  -d "$INC"   # capture memory
curl -s -X POST $BASE/mock/drain           # deliver the BlobCreated event
curl -s -X POST $BASE/snapshot -d "$INC"   # snapshot + copy disks
curl -s -X POST $BASE/mock/drain           # deliver the manifest event
curl -s      $BASE/mock/state              # inspect the whole estate
curl -s      $BASE/mock/ledger/verify      # verify the custody chain
```

`POST /api/mock/reset` reseeds. Event delivery is explicit because Event Grid is
asynchronous — collapsing that into the upload call would hide the gap the
custody design has to tolerate.

Mock-mode artifacts are synthetic and are labelled as such in the image banner,
the blob metadata and the startup log. They must never reach a case file.

### Going live

Set `REACT_MOCK_MODE=false`. `shared/clients.py` then never imports
`shared/mocks/`, and every factory returns the real SDK client. Nothing else
changes: no business logic knows which side of the seam it is on.

## Deploying

```bash
# 1. The enclave, in its own subscription
az deployment group create \
  --resource-group rg-forensic-enclave \
  --template-file iac/main.bicep \
  --parameters sqlAdminObjectId=<aad-group-object-id> \
               sqlAdminLogin=<aad-group-name> \
               targetSubscriptionId=<compromised-sub> \
               targetResourceGroup=rg-victims

# 2. The ledger schema (Person 3 owns this script; see LEDGER_CONTRACT.md
#    for the schema the ChainOfCustody writer requires)
sqlcmd -S <server>.database.windows.net -d reactdfir -G \
       -v FunctionAppName="<function-app-name>" \
       -i iac/scripts/init-sql-ledger.sql

# 3. The acquisition tools and scripts into the repository container
az storage blob upload-batch -d tools -s src/scripts \
       --account-name <storage-account> --auth-mode login

# 4. The functions
cd src/functions && func azure functionapp publish <function-app-name>
```

The Function App's managed identity additionally needs, on the **target**
subscription: `Virtual Machine Contributor`, `Network Contributor` and `Reader`.
Full list in
[`src/functions/ChainOfCustody/LEDGER_CONTRACT.md`](src/functions/ChainOfCustody/LEDGER_CONTRACT.md).

After verifying a real acquisition, redeploy with `lockRetentionPolicy=true`.
Locking is opt-in because it is irreversible: the retention period can then only
be extended, and the container cannot be deleted until every blob ages out.

## Tests

```bash
cd src/functions && .venv/Scripts/python -m pytest tests -q
```

No test contacts Azure. The suite covers SAS properties, containment rules,
generated bootstrap scripts, the snapshot gate and cross-subscription copy,
chunked hashing, ledger idempotency under at-least-once delivery, and the
immutability guarantees the enclave depends on.

## Team

| Area | Owner |
|---|---|
| Cloud orchestration & infrastructure | `@BB-24` |
| Containment, acquisition & hashing | `@gitforg` |
| Data schema, containers & reporting | `@jyeshthachouhan14` |
