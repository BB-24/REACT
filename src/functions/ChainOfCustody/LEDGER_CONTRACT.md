# Evidence ledger contract

`dbo.EvidenceLedger` is an Azure SQL Ledger table configured as append-only.
The schema is provisioned by [`iac/scripts/init-sql-ledger.sql`](../../../iac/scripts/init-sql-ledger.sql)
after the database from `iac/main.bicep` is deployed.

The ChainOfCustody Function inserts these columns:

| Column | Meaning |
| --- | --- |
| `EvidenceId` | Monotonic database-generated evidence identifier |
| `IncidentId` | Incident identifier from blob metadata or the first blob path segment |
| `EvidenceType` | `memory-image`, `disk-image`, `snapshot-manifest`, or `artifact` |
| `BlobUri` | Canonical immutable-storage URL |
| `Sha256Hash` | Lowercase SHA-256 digest of the stored bytes |
| `FileSizeBytes` | Bytes consumed while hashing the blob |
| `CollectionTimestamp` | Acquisition timestamp from blob metadata |
| `CollectorIdentity` | Acquisition initiator identity |

Event Grid delivery is at-least-once. The Function therefore guards inserts by
`(BlobUri, Sha256Hash)` and treats a zero-row insert as a successful duplicate.
No update or delete operation is permitted against the ledger table.
