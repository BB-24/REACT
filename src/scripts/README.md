# Live-Response Memory Acquisition

SOP 2, Phase 2. Volatile memory is captured from a contained host and streamed
into the forensic enclave **without an image file ever touching the target's
disk**.

| Script | Platform | Acquisition tool |
|---|---|---|
| `Acquire-Memory.ps1` | Windows | WinPmem (stdout mode) |
| `acquire-memory.sh` | Linux | AVML, LiME (TCP), or `/proc/kcore` |

## Why no disk write

Three reasons, in order of weight:

1. **Writing evidence destroys evidence.** A multi-gigabyte image lands in
   unallocated space that may hold deleted files, browser artifacts, or malware
   remnants relevant to the same investigation.
2. **The host is compromised.** Staging the dump on disk hands an attacker with
   an active session a readable copy of the artifact being collected, plus the
   opportunity to modify it before upload.
3. **The host may not have room.** A 64 GB VM with a 30 GB OS disk cannot hold
   its own memory image.

## How the streaming works

The obvious approach — pipe the tool into AzCopy — does not work, and neither
does a plain `curl` upload:

- **AzCopy cannot read from stdin.** It requires a file path or a URL.
- **`Put Blob` needs a `Content-Length`** for the whole body, which is unknown
  while the dump is still streaming.
- **Azure Blob Storage rejects `Transfer-Encoding: chunked`**, so streaming the
  length-unknown body is not an option either.

The way through is the block-blob API. Each script reads a fixed-size slice of
the stream, uploads it with **Put Block** (whose length *is* known), and commits
the ordered list of blocks at the end with **Put Block List**. Only one block is
resident at a time.

```
winpmem -  ──┬──> SHA-256 (witness hash)
             └──> [64 MB block] ──> PUT ?comp=block&blockid=…
                  [64 MB block] ──> PUT ?comp=block&blockid=…
                  …
                                    PUT ?comp=blocklist  + x-ms-meta-*
```

Azure allows 50,000 blocks per blob; at the default 64 MB that caps a single
image at 3.2 TB. Both scripts fail loudly rather than silently truncating if the
limit is reached.

### The Linux staging file

`dd` cannot hand a block to `curl` without something to point at, so one block
at a time is staged in `--stage-dir`, defaulting to `/dev/shm`. That is a
**tmpfs — RAM, not a block device**. The script calls `stat -f` and refuses to
run if the staging directory turns out to be disk-backed, which is what keeps
the no-disk-write guarantee honest rather than assumed.

## The witness hash

Both scripts fold a SHA-256 over the stream as it leaves the host and stamp the
digest into blob metadata as `x-ms-meta-witnesssha256`. The `ChainOfCustody`
function independently hashes the stored blob and compares. A mismatch means the
bytes changed between the target and the enclave, and it is logged as an
integrity alert.

This is what distinguishes the chain of custody from a plain checksum: the hash
is computed at the point of acquisition, not after the artifact has already
crossed the network.

## Blob metadata written on commit

| Key | Consumed by |
|---|---|
| `incidentid` | Ledger `IncidentId` |
| `sourcehost` | Ledger `SourceHost` |
| `acquiredutc` | Ledger `AcquiredUtc` |
| `witnesssha256` | Integrity comparison in `ChainOfCustody` |
| `initiatorobjectid` | Ledger `InitiatorObjectId` (Logic App AAD object ID) |
| `acquisitiontool` | Provenance in the final report |

## Usage

Both take the write-only SAS URL returned by `NetworkContainment` as
`uploadUrl`. It expires in 60 minutes, so acquisition must start promptly.

**Windows** — elevated; WinPmem loads a kernel driver:

```powershell
.\Acquire-Memory.ps1 `
    -SasUrl $uploadUrl `
    -IncidentId "INC-2024-0042" `
    -WinPmemPath "C:\Tools\winpmem.exe" `
    -InitiatorObjectId $logicAppObjectId
```

**Linux** — as root:

```bash
sudo ./acquire-memory.sh \
    --sas-url "$UPLOAD_URL" \
    --incident-id "INC-2024-0042" \
    --avml-path /opt/react/avml \
    --initiator-object-id "$LOGIC_APP_OBJECT_ID"
```

Both are invoked by the Logic App through **Azure VM Run Command**, which is why
the SAS arrives as a parameter rather than being minted on the host — the host
is untrusted and gets no standing credential.

## Operational notes

- `-WinPmemArgs` defaults to `-` (stdout). Confirm the WinPmem build in use
  supports stdout output; the script refuses to run with an argument that would
  write to a file.
- LiME mode requires a `lime.ko` built against the target's **exact** running
  kernel version. AVML is preferred precisely because it avoids this.
- `/proc/kcore` is a fallback only. It is ELF-wrapped rather than a flat raw
  image and needs `CONFIG_PROC_KCORE`; note this in the case record when used,
  as it affects how Volatility must be invoked downstream.
- Acquisition must run **after** containment. An attacker with a live session
  can tamper with memory while the dump is in flight.
