/*
  REACT Azure SQL Ledger bootstrap

  Run this script against the database emitted by iac/main.bicep as an
  administrator after deployment. Replace the two sqlcmd variables with the
  Function App managed identity's object ID and display name before execution.

  The table is append-only by design. Event Grid can redeliver an event, so the
  Function uses a guarded INSERT rather than UPDATE/DELETE cleanup.
*/

IF OBJECT_ID(N'dbo.EvidenceLedger', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.EvidenceLedger
    (
        EvidenceId BIGINT IDENTITY(1, 1) NOT NULL
            CONSTRAINT PK_EvidenceLedger PRIMARY KEY CLUSTERED,
        IncidentId NVARCHAR(128) NOT NULL,
        EvidenceType NVARCHAR(64) NOT NULL,
        BlobUri NVARCHAR(2048) NOT NULL,
        Sha256Hash CHAR(64) NOT NULL,
        FileSizeBytes BIGINT NOT NULL,
        CollectionTimestamp DATETIMEOFFSET(7) NOT NULL,
        CollectorIdentity NVARCHAR(255) NOT NULL,
        CONSTRAINT UQ_EvidenceLedger_BlobDigest UNIQUE (BlobUri, Sha256Hash)
    )
    WITH (LEDGER = ON (APPEND_ONLY = ON));
END;
GO

/*
  The Function identity needs only to read the duplicate guard and append rows.
  Keep the identity name/object ID supplied out-of-band; do not commit either
  value to source control.
*/
IF NOT EXISTS (
    SELECT 1
    FROM sys.database_principals
    WHERE name = N'$(FUNCTION_APP_PRINCIPAL_NAME)'
)
BEGIN
    CREATE USER [$(FUNCTION_APP_PRINCIPAL_NAME)]
        FROM EXTERNAL PROVIDER
        WITH SID = 0x$(FUNCTION_APP_PRINCIPAL_OBJECT_ID_HEX), TYPE = E;
END;
GO

GRANT SELECT, INSERT ON dbo.EvidenceLedger
    TO [$(FUNCTION_APP_PRINCIPAL_NAME)];
GO