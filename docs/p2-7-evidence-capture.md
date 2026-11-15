# P2-7 end-to-end acquisition evidence

The acceptance test in
[`src/functions/tests/test_p2_7_end_to_end_acquisition.py`](../src/functions/tests/test_p2_7_end_to_end_acquisition.py)
executes the same mock seams used by the acquisition Function:

1. `MemoryAcquisition` dispatches the memory script to the test VM `web-01`
   for incident `TEST-001`.
2. The simulated stream writes a blob to the `evidence` container and records
   a successful `PutBlob` storage operation with a UTC timestamp, byte count,
   and SHA-256 digest.
3. The queued `Microsoft.Storage.BlobCreated` event is delivered to
   `ChainOfCustody`, which streams the blob and records the digest.
4. The test queries the ledger using the equivalent of:

   ```sql
   SELECT ArtifactType, Sha256Hash, SizeBytes, RecordedUtc
   FROM dbo.EvidenceLedger
   WHERE IncidentId = 'TEST-001'
     AND ArtifactType = 'memory-image';
   ```

The test asserts that the witness hash, storage-operation hash, and ledger
hashes are identical, that the ledger timestamp is present, and that the
append-only ledger chain remains intact. The test output can be used in a
presentation to show the timestamped SHA-256 custody record without exposing
credentials or live infrastructure.
