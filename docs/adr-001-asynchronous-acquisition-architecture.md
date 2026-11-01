# Architecture Decision Record (ADR 001)
# Asynchronous Forensic Acquisition & Compute Hosting Architecture

**Status**: Approved & Implemented  
**Date**: 2026-11-01  
**Scope**: Project REACT Infrastructure, Orchestration & Execution Architecture  
**Target Environment**: Microsoft Azure (`centralindia`), Azure for Students Subscription  

---

## 1. Context & Business Drivers

REACT (Real-time Evidence Acquisition, Containment and Triage) is an automated digital forensics and incident response (DFIR) platform deployed on Microsoft Azure. Its core responsibilities include:

1. **Automated Incident Response & Containment**: Enforcing network isolation via dynamic deny-by-default Network Security Groups (NSGs) with storage egress exceptions, while honoring policy overrides for systems tagged `Critical-Infrastructure=True`.
2. **Volatile Memory Acquisition**: Live-response RAM acquisition from compromised Windows hosts (via WinPmem) and Linux hosts (via AVML) streaming directly to cloud storage without landing raw multi-gigabyte memory images on target disks.
3. **Non-Volatile Disk Snapshotting**: Point-in-time Azure managed disk snapshots copied cross-subscription into the forensic enclave.
4. **Cryptographic Chain of Custody**: Chunked SHA-256 integrity verification (matching host witness hashes) and immutable append-only records written to Azure SQL Database Ledger.
5. **WORM Storage & Legal Hold**: Time-based retention policies (7-year / 2,555 days) and active legal holds on evidence containers.

### Key Architectural Challenges Identified

1. **Hosting Quota Failure (Problem A)**:  
   The initial infrastructure (`iac/main.bicep`) specified an `EP1` (Elastic Premium) App Service Plan for Azure Functions. Deployment failed because the Azure for Students subscription has a hard quota limit of **0 EP1 vCPUs** in `centralindia` (Current: 0, Limit: 0, Required: 1). Requesting quota increases on student subscriptions is not approved.

2. **Long-Running Execution & HTTP Gateway Limits (Problem B)**:  
   The platform specifies `ACQUISITION_TIMEOUT_SECONDS=5400` (90 minutes) to capture physical RAM from high-capacity virtual machines. A synchronous HTTP-triggered function model cannot support this because:
   - Azure HTTP load balancers and front-ends enforce a hard gateway timeout of **230 seconds** (~3.8 minutes).
   - Standard Consumption functions enforce a **10-minute maximum execution limit**.
   - Synchronous HTTP requests cannot survive transient network disconnects, worker restarts, or target VM delays.

3. **Legal Hold Tag Rejection (Problem C)**:  
   The template previously set `legalHoldTags = ['react-active-investigation']`. Azure Storage rejected this with `InvalidValuesForRequestParameters: LegalHold.Tags`. Azure Storage REST API and ARM require legal hold tags to be nonempty alphanumeric strings between 3 and 23 characters (no hyphens, underscores, or punctuation).

4. **Operational Insights Integration (Problem D)**:  
   The `Microsoft.OperationalInsights` resource provider required registration and Application Insights needed connection to an explicit Log Analytics Workspace rather than a deprecated classic component.

---

## 2. Evaluation of Alternative Hosting & Execution Architectures

We evaluated four execution and hosting options against project requirements and constraints:

| Evaluation Criteria | Option 1: Azure Functions Flex Consumption | Option 2: Azure Container Apps Jobs (ACA) | Option 3: Queue-Triggered Azure Functions on Basic B1 (Selected) | Option 4: Azure Durable Functions |
|---|---|---|---|---|
| **Max Execution Duration** | ⚠️ Capped at 60 minutes. Cannot satisfy 90-minute (`5400s`) requirement. | ✅ Up to 24 hours (86,400s) per execution. | ✅ Unbounded / Configurable via `host.json` (`functionTimeout: 02:00:00` or `-1`). | ⚠️ Depends on underlying hosting plan. Capped if on Consumption. |
| **Python Runtime Compatibility** | ✅ Python 3.10, 3.11 supported. | ✅ Full control via custom container (Python 3.11 + system ODBC libs). | ✅ Full native Python v2 programming model (`azure-functions`). | ⚠️ Python Durable Functions has higher orchestration overhead and external dependencies. |
| **Windows & Linux Acquisition** | ✅ Dispatches Run Command. | ✅ Dispatches Run Command. | ✅ Dispatches Run Command. | ✅ Dispatches Run Command. |
| **VNet Integration & Private Endpoints** | ⚠️ Requires dedicated delegated subnet; regional availability restricted. | ⚠️ Requires ACA Environment with delegated subnet infrastructure (`Microsoft.App/environments`). | ✅ Direct support for Regional VNet Integration into existing `Function-Integration-Subnet` (`Microsoft.Web/serverFarms`). | ⚠️ Depends on plan (requires Premium or Dedicated plan). |
| **Existing VNet Delegation Compatibility** | ❌ Conflict: existing subnet delegated to `Microsoft.Web/serverFarms`. | ❌ Conflict: requires destroying/recreating subnet with `Microsoft.App/environments`. | ✅ **Zero Conflict**: Matches existing provisioned subnet delegation `Microsoft.Web/serverFarms`. | ✅ Matches `Microsoft.Web/serverFarms`. |
| **Managed Identity & RBAC** | ✅ System-assigned managed identity supported. | ✅ System-assigned managed identity supported. | ✅ Native System-assigned managed identity supported. | ✅ Supported. |
| **Queue-Based Asynchronous Processing** | ✅ Storage queue triggers supported. | ✅ KEDA queue scaler (`azure-queue`). | ✅ Native `@app.queue_trigger` with poison queue handling. | ⚠️ Uses Azure Storage Tables/Blobs/Queues task hubs internally. |
| **Azure for Students Quota (`centralindia`)** | ❌ Unverified / frequently restricted in student subscriptions. | ⚠️ Container Apps quota variable by region; student subscriptions can face deployment quota limits. | ✅ **Verified Available**: Basic B1 Linux App Service quota is 10 instances in Azure for Students. | ❌ Requires EP1 or App Service Plan for VNet + long run. |
| **Cost & Idle Footprint** | ✅ Scale-to-zero when idle. | ✅ Scale-to-zero when idle (180,000 vCPU-s free/mo). | ⚠️ ~$13/month dedicated compute (fits well within $100 student credit budget). | ⚠️ Dependent on plan. |
| **Operational & Deployment Complexity** | ⚠️ New CLI preview extensions, packaging requirements. | ❌ High: Requires Azure Container Registry (ACR), Docker build/push pipeline, image versioning. | ✅ **Lowest**: Standard `func azure functionapp publish` or zip deploy; 100% test suite compatibility. | ⚠️ Requires Durable task hubs, orchestrator + entity function refactoring. |
| **Retry & Recovery Behavior** | ✅ Standard queue retry. | ✅ Job retry on non-zero exit code. | ✅ Native visibility timeout, max dequeue count (5), dead-letter poison queue (`acquisition-jobs-poison`). | ✅ Built-in checkpointing and replay. |

---

## 3. Architectural Decision

### 1. Hosting Plan: Dedicated App Service Plan (Basic B1 Linux)
- **SKU**: `B1` (Tier: `Basic`, Kind: `linux`, `reserved: true`).
- **Rationale**:
  1. Resolves the EP1 quota denial on Azure for Students immediately.
  2. Retains seamless VNet Integration into the **already provisioned** `Function-Integration-Subnet` (`reactdemo-vnet-xuwxajwx`) without requiring subnet deletion or delegation changes.
  3. Supports execution durations exceeding 90 minutes by setting `"functionTimeout": "02:00:00"` in `host.json`.
  4. Preserves 100% of the existing repository code, mock infrastructure, unit tests, and Azure Functions CLI deployment tooling.

### 2. Asynchronous Messaging & Decoupled Job Workflow
- **Messaging Service**: Azure Queue Storage on existing Storage Account `reactdemoencxuwxajwx`.
- **Queues**:
  - `acquisition-jobs`: Primary queue for acquisition dispatch tasks.
  - `acquisition-jobs-poison`: Dead-letter queue for failed acquisitions after 5 retry attempts.
- **Workflow**:
  1. **Ingestion & Validation**: Sentinel alert or API request hits `POST /api/acquire` or Logic App. Request is validated, target VM existence checked, and a unique `jobId` (`job-<uuid>`) is generated.
  2. **Job Enqueue & Immediate 202 Response**: A job message is committed to `acquisition-jobs` with correlation IDs. The API immediately returns HTTP `202 Accepted` with a `statusUrl` (latency < 2 seconds), avoiding the 230-second gateway timeout entirely.
  3. **Queue-Driven Worker Processing**: Worker pulls message, sets status to `Processing`, mints 60-minute write-only SAS for evidence storage and read-only SAS for tools, and dispatches the Managed Run Command to the target VM.
  4. **Target Streaming via Put Block**: WinPmem (Windows) or AVML (Linux) streams raw memory to stdout; bootstrap scripts (`Acquire-Memory.ps1` / `acquire-memory.sh`) read the stream and execute chunked `Put Block` operations directly against Azure Blob Storage, terminating with `Put Block List`.
  5. **Event Grid Notification**: Upon successful upload, Azure Storage fires `Microsoft.Storage.BlobCreated`. Event Grid webhook triggers `ChainOfCustody`.
  6. **Ledger Integrity Recording**: `ChainOfCustody` computes SHA-256 chunk-by-chunk, matches the host witness hash, and appends an immutable record to `dbo.EvidenceLedger`.
  7. **Status Polling**: Orchestrators poll `GET /api/status?incidentId=<id>` or `GET /api/jobs/<jobId>` until status is `Completed` or `Failed`.

### 3. Legal Hold Configuration
- **Parameter**: `legalHoldTags` updated to `['reacthold']`.
- **Rationale**: Complies with Azure Storage naming rules: 3–23 alphanumeric characters `[a-zA-Z0-9]`, no hyphens or special symbols.

### 4. Monitoring & Observability
- **Log Analytics Workspace**: Provisioned as `reactdemo-law-<suffix>` (`Microsoft.OperationalInsights/workspaces`, SKU `PerGB2018`).
- **Application Insights**: Linked to `logAnalyticsWorkspace.id` via `WorkspaceResourceId`.

---

## 4. Preservation of Existing Environment

The following pre-existing resources are strictly preserved and reused:
- **Storage Account**: `reactdemoencxuwxajwx` (containers, immutability policies, and existing blobs retained; queues added incrementally).
- **SQL Server & Database**: `reactdemo-sql-xuwxajwx` / `reactdemodfir` (Ledger configuration and database files intact).
- **Key Vault**: `reactdemo-kv-xuwxajwx` (purge protection, access policies, and secrets preserved).
- **Virtual Network & Subnets**: `reactdemo-vnet-xuwxajwx` (`Forensic-Enclave-Subnet` and `Function-Integration-Subnet` preserved).
- **Private Endpoints & DNS**: `reactdemoencxuwxajwx-blob-pe` and `privatelink.blob.core.windows.net` preserved.
- **Event Grid**: `reactdemo-evidence-topic` preserved.
- **User-Assigned Identity**: `reactdemo-legalhold-xuwxajwx` preserved.

---

## 5. Summary of Consequences

### Positive
- Deployment succeeds on Azure for Students without quota request dependencies.
- 90-minute acquisition jobs execute reliably without HTTP gateway timeout disconnections.
- Evidence chain of custody remains cryptographically verifiable and WORM-compliant.
- Zero destructive modifications to already provisioned Azure infrastructure.

### Operational Considerations
- The B1 Linux App Service Plan runs continuously (~$13/month). Users must stop/deallocate victim VMs and manage the Function App after demo sessions to preserve student credits.

