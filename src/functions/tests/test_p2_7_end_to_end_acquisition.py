"""P2-7 acceptance test: memory acquisition through storage and SQL custody."""

import hashlib

from MemoryAcquisition import handle_acquisition
from shared import ledger, mocks


def test_test_001_acquisition_captures_blob_ledger_hash_and_upload_log(
    mock_estate, post
):
    """Run the simulated memory script and capture every evidence checkpoint."""
    incident_id = "TEST-001"
    response = handle_acquisition(
        post(
            {
                "IncidentId": incident_id,
                "TargetVM": (
                    "/subscriptions/00000000-0000-0000-0000-000000000001/"
                    "resourceGroups/rg-victims/providers/Microsoft.Compute/"
                    "virtualMachines/web-01"
                ),
                "InitiatorObjectId": "p2-7-test-collector",
            }
        )
    )

    assert response.status_code == 200
    upload = mock_estate.storage_operations[-1]
    assert upload["operation"] == "PutBlob"
    assert upload["status"] == "Succeeded"
    assert upload["container"] == "evidence"
    assert upload["sizeBytes"] > 0
    assert upload["timestamp"]

    blob = next(
        blob
        for blob in mock_estate.blobs.values()
        if blob.metadata.get("incidentid") == incident_id
    )
    expected_hash = hashlib.sha256(blob.data).hexdigest()
    assert blob.sha256() == expected_hash
    assert upload["sizeBytes"] == len(blob.data)
    assert blob.metadata["witnesssha256"] == expected_hash

    assert mock_estate.ledger_rows == []
    delivered = mocks.drain_events()
    assert delivered[0]["status"] == "recorded"

    row = ledger.find_evidence(incident_id, "memory-image")
    assert row is not None
    assert row["Sha256Hash"] == expected_hash
    assert row["SizeBytes"] == len(blob.data)
    assert row["RecordedUtc"]

    # This is the presentation-ready timestamped custody evidence.
    assert row["RecordedUtc"] >= upload["timestamp"]
    assert mock_estate.verify_ledger() == (True, None)
