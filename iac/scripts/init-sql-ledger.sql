-- ============================================================================
-- Project REACT: Azure SQL Database Ledger & Job Tracking Schema
-- 
-- Requirement mapping:
--   REQ-3.5.3  Azure SQL Database Ledger (Append-Only) for tamper-evident
--              cryptographic chain of custody records.
--   REQ-3.3.4  Asynchronous job state tracking and correlation ID tracking.
--
-- Deployment Instructions:
--   Execute this script against the 'reactdemodfir' database as the Azure AD
--   SQL Administrator (via Azure Cloud Shell, Azure Portal Query Editor, or sqlcmd).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Evidence Ledger Table (Append-Only Ledger)
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE object_id = OBJECT_ID(N'dbo.EvidenceLedger'))
BEGIN
    CREATE TABLE dbo.EvidenceLedger (
        [LedgerEntryId] BIGINT IDENTITY(1,1) NOT NULL,
        [IncidentId] NVARCHAR(128) NOT NULL,
        [BlobUri] NVARCHAR(512) NOT NULL,
        [BlobName] NVARCHAR(256) NOT NULL,
        [ArtifactType] NVARCHAR(64) NOT NULL,
        [SizeBytes] BIGINT NOT NULL,
        [Sha256Hash] NVARCHAR(64) NOT NULL,
        [AcquiredUtc] NVARCHAR(64) NOT NULL,
        [RecordedUtc] NVARCHAR(64) NOT NULL,
        [InitiatorObjectId] NVARCHAR(128) NULL,
        [SourceHost] NVARCHAR(128) NULL,
        [WitnessHash] NVARCHAR(64) NULL,
        [WitnessHashMatch] BIT NULL,
        CONSTRAINT PK_EvidenceLedger PRIMARY KEY CLUSTERED ([LedgerEntryId])
    ) WITH (LEDGER = ON (APPEND_ONLY = ON));

    -- Idempotency index for Event Grid duplicate delivery checks
    CREATE NONCLUSTERED INDEX IX_EvidenceLedger_Dedup
    ON dbo.EvidenceLedger ([BlobUri], [Sha256Hash]);

    -- Lookup index for artifact gating (e.g., verifying memory before disk snapshot)
    CREATE NONCLUSTERED INDEX IX_EvidenceLedger_Lookup
    ON dbo.EvidenceLedger ([IncidentId], [ArtifactType], [LedgerEntryId] DESC);
END
GO

-- ----------------------------------------------------------------------------
-- 2. Asynchronous Acquisition Jobs Table (State & Correlation Tracking)
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE object_id = OBJECT_ID(N'dbo.AcquisitionJobs'))
BEGIN
    CREATE TABLE dbo.AcquisitionJobs (
        [JobId] NVARCHAR(64) NOT NULL,
        [IncidentId] NVARCHAR(128) NOT NULL,
        [TargetVm] NVARCHAR(512) NOT NULL,
        [Platform] NVARCHAR(32) NOT NULL,
        [Status] NVARCHAR(32) NOT NULL, -- Queued, Processing, Uploading, Completed, Failed, TimedOut
        [AttemptCount] INT NOT NULL DEFAULT 1,
        [CreatedAt] DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        [UpdatedAt] DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        [HeartbeatAt] DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        [CompletedAt] DATETIME2 NULL,
        [ArtifactBlobUri] NVARCHAR(512) NULL,
        [ArtifactSha256] NVARCHAR(64) NULL,
        [WitnessHash] NVARCHAR(64) NULL,
        [RunCommandName] NVARCHAR(128) NULL,
        [ErrorMessage] NVARCHAR(MAX) NULL,
        [PartialEvidenceLogged] BIT NOT NULL DEFAULT 0,
        [CorrelationId] NVARCHAR(64) NULL,
        CONSTRAINT PK_AcquisitionJobs PRIMARY KEY CLUSTERED ([JobId])
    );

    CREATE NONCLUSTERED INDEX IX_AcquisitionJobs_Incident
    ON dbo.AcquisitionJobs ([IncidentId], [Status]);

    CREATE NONCLUSTERED INDEX IX_AcquisitionJobs_Heartbeat
    ON dbo.AcquisitionJobs ([Status], [HeartbeatAt]);
END
GO

-- ----------------------------------------------------------------------------
-- 3. Entra ID Managed Identity Security Provisioning
-- Replace '<FUNCTION_APP_NAME>' with your deployed Function App name
-- (e.g. reactdemo-fn-xuwxajwx) when executing manually.
-- ----------------------------------------------------------------------------
/*
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'<FUNCTION_APP_NAME>')
BEGIN
    CREATE USER [<FUNCTION_APP_NAME>] FROM EXTERNAL PROVIDER;
    ALTER ROLE db_datareader ADD MEMBER [<FUNCTION_APP_NAME>];
    ALTER ROLE db_datawriter ADD MEMBER [<FUNCTION_APP_NAME>];
END
GO
*/

