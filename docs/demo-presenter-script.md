# REACT Mid-Semester Demo Presenter Script (3–5 Minutes)

> **MANDATORY REVIEWER NOTICE**  
> **SIMULATED — synthetic data; no Azure resources or live machines touched.**  
> *This demonstration is a process-local prototype simulation of cloud forensic automation. No live machines, Azure credentials, or cloud resources are accessed.*

---

## Presentation Overview

- **Presenter Role:** Incident Response Automation Engineer / Forensic Software Engineer
- **Audience:** Faculty Evaluators, Project Reviewers, and Peer Engineers
- **Target Duration:** 3 to 5 minutes
- **Demo Command:** `python scripts/demo.py` (or web dashboard: `python scripts/demo.py --web`)

---

## Speaker Script & Step-by-Step Flow

### 1. Problem Statement & Motivation (0:00 – 0:45)

> *"Good morning/afternoon, evaluators. Today we are presenting Project **REACT** — the **Rapid Evidence Acquisition & Containment Toolkit** for cloud incident response.*
>
> *When a cloud virtual machine is compromised — for instance, by ransomware or an active C2 implant — security operations face a fundamental dilemma:*
>
> *If you power down or deallocate the VM, volatile memory is instantly wiped, destroying injection artifacts, decrypted keys, and active network connections.*
> *If you leave the VM running, the attacker can move laterally or wipe memory before investigators can react.*
>
> *REACT solves this by orchestrating an immediate, policy-driven network containment followed by non-destructive, live-response memory streaming and cross-subscription disk snapshotting, all bound into an immutable, cryptographic chain of custody."*

---

### 2. Architecture & Simulation Boundary (0:45 – 1:30)

> *"Before diving into the run, let's establish the safety boundary of this mid-semester prototype:*
>
> *This is an **offline simulation**. We designed REACT with a strict architectural seam in `shared.clients`. When `REACT_MOCK_MODE=true`, the system talks to an in-memory simulated Azure fabric:*
> - *The **Compromised Subscription** (`0000...0001`) holds our victim VMs and production NICs.*
> - *The **Forensic Enclave Subscription** (`0000...00e1`) holds our immutable evidence blob container under legal hold and our SQL Ledger verification engine.*
> - *If any component attempts to request real Entra ID tokens, our `MockCredential` fails closed.*
>
> *Every artifact and digest shown today is strictly synthetic and produced locally on this machine."*

---

### 3. Live Scenario 1: High-Severity Incident Response (1:30 – 3:00)

*(Action: Run `python scripts/demo.py --scenario 1` in terminal OR click 'Run Scenario 1' in the Web Dashboard at `http://127.0.0.1:8080`)*

> *"Let's trigger **Scenario 1**: Sentinel detects high-severity activity on Windows web server `web-01`.*
>
> *Watch the stages execute:*
>
> 1. **Ingress & Validation:** *The Sentinel alert payload is verified against our strict JSON schema contract (`docs/payload-contract.json`).*
> 2. **Network Containment:** *Notice that `web-01` is **isolated, not deallocated**. Our `NetworkContainment` engine swaps a deny-by-default isolation NSG onto the primary NIC, blocking all inbound traffic and all outbound lateral movement, while preserving a single egress rule to Azure Storage for evidence transmission. The previous NSG ID is preserved for post-incident recovery.*
> 3. **Volatile Memory Streaming (SOP 2 Phase 2):** *The OS is identified as Windows. A PowerShell bootstrap is synthesized and dispatched via Azure Run Command. Crucially: **zero bytes of the dump are written to the victim's disk**. WinPmem streams the image straight into our enclave container.*
> 4. **Chain-of-Custody & Ledger (SOP 2 Phase 3):** *As the blob lands, Event Grid fires `BlobCreated`. Our `ChainOfCustody` service hashes the blob stream chunk-by-chunk in 8 MB buffers to preserve memory efficiency. It computes the SHA-256 digest, validates it against the target's witness hash, and appends an immutable block to our SQL Ledger hash chain.*
> 5. **Non-Volatile Disk Snapshots:** *Per REQ-3.4.1, disk snapshotting is strictly gated on the memory ledger entry. Once verified, crash-consistent snapshots of the OS disk and data disk are generated and copied across the subscription boundary into the Forensic Enclave. A manifest blob is written and hashed.*
> 6. **Forensic Analysis & Sanitized Record:** *Our analyzer extracts timeline events from evidence fixtures. Note that all generated case metadata is strictly sanitized — no SAS tokens or bearer credentials are leaked."*

---

### 4. Scenario 2: Critical Infrastructure Policy Bypass (3:00 – 3:45)

*(Action: Run `python scripts/demo.py --scenario 2`)*

> *"Now consider a real-world dilemma: What happens when the compromised VM is a hospital life-safety system, SCADA controller, or core banking database? Severing network links could cause catastrophic operational harm.*
>
> *In **Scenario 2**, our Linux host `db-02` is tagged `Critical-Infrastructure: True`.*
>
> *Notice the outcome in Stage 2:*
> - *Network isolation is **BYPASSED** per organizational policy, keeping critical services online.*
> - *However, forensic acquisition does not stop! The pipeline proceeds directly to acquire volatile memory using AVML in tmpfs (`/dev/shm`), takes disk snapshots, and records the full chain of custody in the Ledger.*
>
> *This demonstrates policy-aware incident orchestration."*

---

### 5. Error Transparency & Next Steps (3:45 – 4:30)

*(Action: Run `python scripts/demo.py --scenario 3`)*

> *"In **Scenario 3**, when an invalid target or containment failure occurs, REACT halts downstream stages immediately. It does not fabricate success-shaped fallbacks or produce false evidence.*
>
> *In summary:*
> - **129 Automated Tests** *validate this entire baseline (`pytest -q`), including contract validation, mock isolation, and ledger digest chaining.*
> - *For the final semester, our next steps are connecting the real Logic App in Azure, standing up the Bicep-provisioned Key Vault and Azure SQL Ledger, and running containerized Volatility 3 plugins in Azure Container Instances.*
>
> *Thank you, and we welcome your questions."*

---

## Presenter Q&A Anticipation Guide

| Question | Recommended Answer |
| :--- | :--- |
| **Why not just stop/deallocate the VM?** | Deallocating a VM destroys volatile RAM instantly. Injected DLLs, rootkits, in-memory malware, and encryption keys are lost forever. Isolation retains power and volatile state while cutting off C2. |
| **Why stream memory instead of writing to disk first?** | Writing a 16 GB raw dump to the victim's disk overwrites unallocated clusters, clobbers NTFS/ext4 journals, and alters file access timestamps — corrupting the very non-volatile evidence you need to analyze next. |
| **Why copy snapshots to a different subscription?** | If an attacker compromised subscription Contributor permissions, they can delete local snapshots. The Forensic Enclave subscription is in an entirely separate RBAC administrative domain. |
| **How is chain of custody proven?** | `ChainOfCustody` streams the blob from storage, hashes it with SHA-256, verifies it matches the host witness hash, and appends the entry to an Azure SQL Ledger table where each block contains `_PreviousDigest` and `_LedgerDigest` forming an unbroken cryptographic hash chain. |
| **Is any real Azure money spent during this demo?** | No. `REACT_MOCK_MODE=true` runs process-locally on synthetic mocks. Zero Azure API calls or billable cloud resources are utilized. |
