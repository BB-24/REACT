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

## Fetching the tool (REQ-3.3.2)

Neither script assumes the acquisition binary is already on the host. Given
`-ToolUrl` / `--tool-url` -- a **read-only, blob-scoped** SAS for the tool
repository container -- it fetches WinPmem or AVML on demand and deletes it
again on the way out.

Pass `-ToolSha256` / `--tool-sha256` whenever you can. It is the only thing
standing between a tampered tool repository and a forensic binary executing as
SYSTEM or root on the target; without it the scripts run the download and warn.

The read token is exposed to the compromised host exactly as the upload token
is. The worst case is bounded: it is read-only, scoped to one blob, and grants
no path to the evidence container, which lives under a different token entirely.

On Linux the binary is staged in `/dev/shm`, so **nothing** reaches the block
device. On Windows the ~1 MB binary does land in `%TEMP%`: there is no tmpfs
equivalent, and a kernel driver cannot be loaded from memory. That is a bounded
write of a file we supplied, removed in the `finally` block. The multi-gigabyte
*image* -- the artifact REQ-3.3.4 is actually about -- still never touches disk.

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
    -ToolUrl $winPmemReadSasUrl `
    -ToolSha256 $winPmemSha256 `
    -InitiatorObjectId $logicAppObjectId
```

(Or point `-WinPmemPath` at a binary already staged on the host and omit
`-ToolUrl` entirely.)

**Linux** — as root:

```bash
sudo ./acquire-memory.sh \
    --sas-url "$UPLOAD_URL" \
    --incident-id "INC-2024-0042" \
    --tool-url "$AVML_READ_SAS_URL" \
    --tool-sha256 "$AVML_SHA256" \
    --initiator-object-id "$LOGIC_APP_OBJECT_ID"
```

(Or point `--avml-path` at a binary already staged on the host and omit
`--tool-url` entirely.)

Both are invoked by the `MemoryAcquisition` function through **Azure Managed Run
Command**, which is why the SAS arrives as a parameter rather than being minted
on the host — the host is untrusted and gets no standing credential. Every
parameter is passed as a *protected* parameter, so none of the three URLs can be
read back off the VM's run-command resource afterwards.

`MemoryAcquisition` generates a small bootstrap that downloads this script and
its tool from the repository, then invokes it. That keeps the reviewed
acquisition logic in one versioned artifact instead of re-emitting it from
Python on every incident.

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
