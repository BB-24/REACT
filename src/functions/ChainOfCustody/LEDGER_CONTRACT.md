# Chain-of-Custody Ledger Contract

Interface agreement between **ChainOfCustody** (Person 2, `@gitforg`) and the
ledger schema in `iac/scripts/init-sql-ledger.sql` (Person 3,
`@jyeshthachouhan14`).

`iac/scripts/init-sql-ledger.sql` is outside Person 2's CODEOWNERS boundary, so
this file states the contract rather than editing the schema. Person 3 owns the
DDL below and the script that applies it.

## Required DDL

An **append-only ledger table**, not an ordinary table and not an *updatable*
ledger table. An updatable ledger table permits UPDATE and DELETE and records
the prior version in a history table; that is right for business data whose edit
history must be provable, and wrong here. A custody record must never be edited
at all, and the engine refusing the statement outright is a stronger guarantee
than an audit trail showing that someone tried.

```sql
CREATE TABLE dbo.EvidenceLedger
(
    LedgerEntryId      BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    IncidentId         NVARCHAR(128)  NOT NULL,
    BlobUri            NVARCHAR(1024) NOT NULL,
    BlobName           NVARCHAR(512)  NOT NULL,
    ArtifactType       NVARCHAR(64)   NOT NULL,
    SizeBytes          BIGINT         NOT NULL,
    Sha256Hash         CHAR(64)       NOT NULL,
    AcquiredUtc        NVARCHAR(64)   NOT NULL,
    RecordedUtc        NVARCHAR(64)   NOT NULL,
    InitiatorObjectId  NVARCHAR(128)  NOT NULL,
    SourceHost         NVARCHAR(256)  NOT NULL
)
WITH (LEDGER = ON (APPEND_ONLY = ON));

-- Backs the WHERE NOT EXISTS duplicate guard; Event Grid delivers at least once.
CREATE INDEX IX_EvidenceLedger_Blob
    ON dbo.EvidenceLedger (BlobUri, Sha256Hash);

-- Backs ledger.find_evidence, the REQ-3.4.1 gate that blocks disk snapshotting
-- until a memory-image row exists.
CREATE INDEX IX_EvidenceLedger_Incident
    ON dbo.EvidenceLedger (IncidentId, ArtifactType);
```

## Notes for Person 3

- **Column names and order are load-bearing.** `shared/ledger.py` builds its
  INSERT from the `COLUMNS` tuple; renaming a column breaks the write.
- **INSERT only.** A ledger table rejects UPDATE and DELETE, which is why the
  function deduplicates at insert time with `WHERE NOT EXISTS` instead of
  cleaning up after a replayed Event Grid delivery.
- **Timestamps are stored as ISO-8601 strings** (`NVARCHAR`) rather than
  `DATETIME2`. Offsets survive round-tripping intact, so the recorded time is
  unambiguous in an evidentiary context. Switching to `DATETIMEOFFSET` is fine
  by us — say so and we will adapt the writer.
- **`InitiatorObjectId`** is the AAD object ID of the Logic App managed identity
  that triggered the response, read from the blob metadata the acquisition
  script stamps, and falling back to the `LOGIC_APP_PRINCIPAL_ID` app setting.
- **ReportGenerator** should read `Sha256Hash`, `AcquiredUtc` and
  `InitiatorObjectId` for the custody section of the PDF. The
  `dbo.vw_IncidentCustody` view joins in each row's ledger commit time, which
  comes from the ledger's own transaction record and so cannot be back-dated.
- **`ArtifactType`** is one of `memory-image`, `disk-image`, `snapshot-manifest`
  or `artifact`. `snapshot-manifest` rows are written by DiskSnapshot and name
  every disk snapshot taken for an incident.

## Required application settings

| Setting | Purpose | Example |
|---|---|---|
| `SQL_CONNECTION_STRING` | Ledger connection, AAD auth only | `Driver={ODBC Driver 18 for SQL Server};Server=tcp:react-sql.database.windows.net,1433;Database=reactdfir;Authentication=ActiveDirectoryMsi;Encrypt=yes;` |
| `LEDGER_TABLE` | Override target table | `dbo.EvidenceLedger` |
| `EVIDENCE_CONTAINER` | Enclave container name | `evidence` |
| `EVIDENCE_STORAGE_ACCOUNT` | Enclave storage account | `reactenclave01` |
| `TOOLS_CONTAINER` | Acquisition tool repository | `tools` |
| `REACT_MOCK_MODE` | Run against the simulated estate | `false` |
| `FORENSIC_SUBSCRIPTION_ID` | Enclave subscription (REQ-3.4.3) | GUID |
| `FORENSIC_RESOURCE_GROUP` | Enclave resource group | `rg-forensic-enclave` |
| `FORENSIC_LOCATION` | Region for enclave snapshot copies | `eastus` |
| `ACQUISITION_TIMEOUT_SECONDS` | Run Command timeout | `5400` |
| `HASH_CHUNK_BYTES` | Streaming chunk size | `8388608` |
| `LOGIC_APP_PRINCIPAL_ID` | Fallback initiator object ID | AAD object GUID |
| `SAS_MODE` | `user-delegation` (default) or `key-vault` | `user-delegation` |
| `SAS_TTL_MINUTES` | Upload token lifetime | `60` |
| `KEY_VAULT_URI` | Only when `SAS_MODE=key-vault` | `https://react-kv.vault.azure.net/` |
| `STORAGE_KEY_SECRET_NAME` | Only when `SAS_MODE=key-vault` | `evidence-storage-key` |
| `EVIDENCE_STORAGE_SERVICE_TAG` | Egress allow target for the isolation NSG | `Storage.eastus` |
| `CONTAINMENT_EXTRA_ALLOW_TAGS` | Optional extra egress service tags | `AzureActiveDirectory` |

The Function App's managed identity needs:

- `Storage Blob Data Contributor` **and** `Storage Blob Delegator` on the
  enclave account (the latter is what permits user-delegation SAS minting),
- `Network Contributor` on the target resource group (NSG create, NIC update),
- `Virtual Machine Contributor` on the target resource group (Run Command
  execution and managed-disk snapshot creation),
- `Disk Snapshot Contributor` on the enclave resource group (the
  cross-subscription `CopyStart` destination),
- `Reader` on the target VM,
- a contained database user mapped to its identity, with `INSERT` and `SELECT`
  on the ledger table.
