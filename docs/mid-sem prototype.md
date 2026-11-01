# Mid-Semester Prototype Demo Implementation Plan

## Goal

Prepare REACT as a repeatable, easy-to-follow prototype demonstration of an
incident-response and forensic evidence workflow. A reviewer should be able to
run a synthetic scenario locally, see what each stage did, inspect the resulting
evidence metadata, and reset the demo without an Azure subscription.

This is a **simulation**, not a production incident-response system. The demo
must not contact or isolate real Azure resources, acquire real machine memory,
or imply that synthetic findings are genuine forensic evidence.

## Current state

- The repository has Azure Function components, a Logic App definition, Bicep
  infrastructure, and a process-local simulated Azure estate.
- `REACT_MOCK_MODE=true` is documented in
  [`src/functions/local.settings.sample.json`](../src/functions/local.settings.sample.json).
  Mock mode emits a warning and uses synthetic resources and artifacts.
- Unit, contract, integration, and simulated end-to-end tests exist. The current
  baseline collected 121 tests and `pytest -q` passed during the branch
  assessment.
- The root [`README.md`](../README.md) is still a placeholder. There is no
  `host.json` at the repository root or under `src/functions/`, and the
  registered Functions app currently includes only the memory-acquisition and
  disk-snapshot blueprints. Do not treat the Logic App definition and local
  tests as proof of a connected, locally runnable cloud workflow.
- The forensic analyzer has a separate Docker verification path using
  [`sample-evidence/`](../sample-evidence/).

## Recommended demo scope

Build a small **local demo experience** with:

1. A clear start/reset path and a visible synthetic-data / mock-mode banner.
2. A guided incident scenario that shows the workflow stages and their results.
3. At least three scenarios: high-severity simulated response, critical
   infrastructure bypass, and a simulated failure.
4. An inspectable result showing containment outcome, acquired artifact
   metadata, hash/chain-of-custody status where supported, and analysis output.
5. A README walkthrough and a fallback recording or screenshots.

Keep the experience local and deterministic. Before building the UI, confirm
which existing component handlers can be safely composed in mock mode. Avoid
duplicating production business logic or claiming a full end-to-end workflow
until its stages are actually connected and verified.

## Implementation phases

### Phase 1 — Confirm the demo path and safety boundary

- Trace the existing function routes, mock support, workflow contracts, and
  output data for the proposed scenarios.
- Decide and document the local composition point for the demo. Reuse component
  logic and mock clients; do not call the real Azure SDK in demo mode.
- Identify any missing entrypoints or component handoffs. In particular,
  verify the network-containment route registration and whether a Functions
  host can start from the current repository layout.
- Define a conspicuous label for the interface, logs, and generated artifacts:
  **“SIMULATED — synthetic data; no Azure resources or live machines touched.”**

**Exit criteria:** A documented flow shows each stage, its current implementation
status (implemented, simulated, or not connected), and how the demo remains
offline from Azure.

### Phase 2 — Make local startup predictable

- Add the minimal Azure Functions host configuration and local demo
  configuration only if required by the verified startup path.
- Provide one documented command or launcher to check prerequisites, start the
  local components, and report actionable startup errors.
- Ensure mock mode is explicit and enabled for the demo; fail closed or refuse
  startup if the demo could reach real Azure.
- Add a reset operation that restores the in-memory estate and produces
  repeatable scenario results.
- Keep secrets and real credentials out of sample configuration and demo output.

**Exit criteria:** A clean checkout can start the local demo without Azure
credentials. Startup confirms mock mode, and reset returns the same initial
synthetic state.

### Phase 3 — Implement the guided demo experience

- Provide a simple local dashboard (or a scripted terminal walkthrough if a
  dashboard would delay delivery) with a short scenario selector and a clear
  **Run** and **Reset** action.
- Show progress and per-stage outcomes rather than a single success message.
- Include empty, in-progress, completed, bypassed, and failed states as
  applicable; surface errors instead of showing success-shaped fallbacks.
- Present hashes, timestamps, and chain-of-custody state as synthetic demo
  metadata. Do not expose SAS tokens, credentials, or other bearer secrets.
- Make unsupported or disconnected workflow stages explicit in the UI.

**Exit criteria:** A first-time reviewer can run each scenario, understand the
outcome without reading source code, and distinguish simulated stages from
unimplemented integrations.

### Phase 4 — Verify behavior and safety

- Add focused automated tests for scenario outcomes, reset behavior, displayed
  simulation labels, and failure handling.
- Test that demo startup and each scenario do not instantiate real Azure
  clients or make network calls.
- Test that generated demo output contains no credentials or SAS URLs and is
  marked synthetic.
- Run the existing full suite and the repository's configured Ruff checks.
- If the Docker analyzer is included in the live demo, run its local verification
  separately and confirm the timeline output is generated from the synthetic
  fixtures.

**Exit criteria:** Existing tests remain green; the demo-specific checks prove
mock-only execution and the promised output shape. Record commands and results.

### Phase 5 — Package the mid-semester presentation

- Replace the placeholder in [`README.md`](../README.md) with prerequisites,
  setup, launch, scenarios, reset, expected results, and troubleshooting.
- Add a 3–5 minute presenter script: problem, architecture, one scenario,
  evidence/ledger result, limitations, and next steps.
- Add a small architecture diagram and clearly label which boxes are mocked,
  locally executed, cloud deployment artifacts, or not yet integrated.
- Capture screenshots or a short recording after the final verified run.
- Prepare a fallback: screenshots and recorded output, in case the live demo
  machine or Docker setup fails.

**Exit criteria:** Another team member can follow the README and reproduce the
demo. Presentation materials consistently call it a simulated prototype.

## Suggested delivery order

1. Finish Phase 1 before choosing a UI or changing the runtime wiring.
2. Prioritize a reliable startup, reset, and two or three truthful scenarios.
3. Add the dashboard only after the scenario runner and outputs are stable.
4. Complete tests and safety checks before recording the demo.
5. Keep real Azure deployment, live containment, and real evidence acquisition
   out of the mid-semester demo scope.

## Acceptance checklist

- [ ] One documented local start command and one reset path.
- [ ] Mock mode is explicit, visibly indicated, and cannot silently fall back to
  real Azure for the demo.
- [ ] High-severity, critical-infrastructure-bypass, and failure scenarios are
  repeatable and clearly explained.
- [ ] Results identify synthetic evidence and show only safe metadata.
- [ ] Disconnected or unimplemented stages are disclosed.
- [ ] Existing and new automated tests pass; validation commands and results are
  recorded in the README or presentation notes.
- [ ] README, architecture diagram, presenter script, and fallback capture are
  ready for review.
