"""Lightweight local HTTP server for the REACT Interactive Demo Dashboard.

Zero external dependencies: uses Python standard library http.server.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .orchestrator import SIMULATION_LABEL, get_orchestrator

LOGGER = logging.getLogger("react.demo.server")

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>REACT — Automated Forensic Incident Response Prototype</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #0a0e17;
      --bg-card: rgba(18, 26, 43, 0.75);
      --bg-card-hover: rgba(28, 40, 65, 0.85);
      --border-color: rgba(66, 99, 155, 0.25);
      --border-accent: rgba(56, 189, 248, 0.4);
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent-blue: #38bdf8;
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --accent-purple: #a855f7;
      --gradient-brand: linear-gradient(135deg, #38bdf8 0%, #6366f1 50%, #a855f7 100%);
      --gradient-sim: linear-gradient(90deg, #f59e0b 0%, #d97706 100%);
      --glow-blue: 0 0 25px rgba(56, 189, 248, 0.25);
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      background-image:
        radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(99, 102, 241, 0.08) 0%, transparent 40%);
      background-attachment: fixed;
    }

    /* Simulation Alert Banner */
    .sim-banner {
      background: var(--gradient-sim);
      color: #0f172a;
      font-weight: 700;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 0.6rem 1rem;
      text-align: center;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      box-shadow: 0 2px 10px rgba(245, 158, 11, 0.3);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .sim-banner .tag {
      background: #0f172a;
      color: #fbbf24;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
    }

    .container {
      max-width: 1380px;
      margin: 0 auto;
      padding: 2rem 1.5rem;
    }

    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border-color);
      flex-wrap: wrap;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .brand-icon {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      background: var(--gradient-brand);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.5rem;
      color: #ffffff;
      box-shadow: var(--glow-blue);
    }
    .brand-title h1 {
      font-size: 1.6rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(to right, #f8fafc, #94a3b8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-title p {
      color: var(--text-muted);
      font-size: 0.875rem;
    }

    .header-actions {
      display: flex;
      gap: 0.75rem;
      align-items: center;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .badge-mock {
      background: rgba(16, 185, 129, 0.15);
      color: var(--accent-emerald);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .badge-mock::before {
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-emerald);
      box-shadow: 0 0 8px var(--accent-emerald);
    }

    .btn {
      font-family: var(--font-sans);
      font-size: 0.875rem;
      font-weight: 600;
      padding: 0.6rem 1.25rem;
      border-radius: 8px;
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    .btn-primary {
      background: var(--gradient-brand);
      color: #ffffff;
      box-shadow: var(--glow-blue);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 0 30px rgba(56, 189, 248, 0.4);
    }
    .btn-outline {
      background: rgba(18, 26, 43, 0.6);
      color: var(--text-main);
      border-color: var(--border-color);
    }
    .btn-outline:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-accent);
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none !important;
    }

    /* Grid Layout */
    .main-grid {
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 1.75rem;
      align-items: start;
    }
    @media (max-width: 1024px) {
      .main-grid { grid-template-columns: 1fr; }
    }

    /* Scenario Selection Panel */
    .sidebar {
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }

    .card {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 1.25rem;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .card:hover {
      border-color: var(--border-accent);
    }

    .card-title {
      font-size: 1rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .scenario-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .scenario-item {
      padding: 1rem;
      border-radius: 10px;
      border: 1px solid var(--border-color);
      background: rgba(10, 14, 23, 0.6);
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
    }
    .scenario-item:hover {
      border-color: var(--accent-blue);
      background: rgba(56, 189, 248, 0.05);
      transform: translateX(2px);
    }
    .scenario-item.active {
      border-color: var(--accent-blue);
      background: rgba(56, 189, 248, 0.1);
      box-shadow: inset 3px 0 0 var(--accent-blue);
    }

    .scenario-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.4rem;
    }
    .scenario-id {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--accent-cyan);
    }
    .scenario-target {
      font-size: 0.75rem;
      color: var(--text-dim);
    }
    .scenario-name {
      font-weight: 600;
      font-size: 0.9rem;
      color: var(--text-main);
      margin-bottom: 0.25rem;
    }
    .scenario-desc {
      font-size: 0.78rem;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Estate Quick Stats */
    .stat-row {
      display: flex;
      justify-content: space-between;
      padding: 0.4rem 0;
      font-size: 0.8rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--text-muted); }
    .stat-value { font-family: var(--font-mono); font-weight: 600; color: var(--accent-blue); }

    /* Main Execution Stage View */
    .content-panel {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .status-banner {
      padding: 1.25rem;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border: 1px solid var(--border-color);
      background: var(--bg-card);
      flex-wrap: wrap;
      gap: 1rem;
    }
    .status-left h2 {
      font-size: 1.15rem;
      font-weight: 700;
    }
    .status-left p {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    /* Stepper */
    .stages-stepper {
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
    }

    .stage-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.15rem;
      transition: all 0.2s ease;
    }
    .stage-card.completed {
      border-left: 4px solid var(--accent-emerald);
    }
    .stage-card.bypassed {
      border-left: 4px solid var(--accent-amber);
    }
    .stage-card.failed {
      border-left: 4px solid var(--accent-rose);
    }
    .stage-card.skipped {
      border-left: 4px solid var(--text-dim);
      opacity: 0.65;
    }

    .stage-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.4rem;
    }
    .stage-title {
      font-weight: 600;
      font-size: 0.95rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .stage-badge {
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      letter-spacing: 0.04em;
    }
    .badge-completed { background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald); }
    .badge-bypassed { background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); }
    .badge-failed { background: rgba(244, 63, 94, 0.2); color: var(--accent-rose); }
    .badge-skipped { background: rgba(100, 116, 139, 0.2); color: var(--text-dim); }

    .stage-summary {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
    }

    .stage-details {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: #cbd5e1;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
    }
    .tab-btn {
      background: none;
      border: none;
      font-family: var(--font-sans);
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-muted);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .tab-btn:hover { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }
    .tab-btn.active { color: var(--accent-blue); background: rgba(56, 189, 248, 0.1); }

    /* Footer */
    footer {
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border-color);
      text-align: center;
      color: var(--text-dim);
      font-size: 0.8rem;
    }
  </style>
</head>
<body>

  <!-- Mandatory Simulation Banner -->
  <div class="sim-banner">
    <span class="tag">SIMULATION</span>
    <span>SIMULATED — synthetic data; no Azure resources or live machines touched.</span>
    <span class="tag">OFFLINE PROTOTYPE</span>
  </div>

  <div class="container">
    <!-- Header -->
    <header>
      <div class="brand">
        <div class="brand-icon">R</div>
        <div class="brand-title">
          <h1>Project REACT — Incident Response Prototype</h1>
          <p>Automated Network Containment, Live-Response Memory & Disk Forensic Pipeline</p>
        </div>
      </div>
      <div class="header-actions">
        <span class="badge badge-mock">MOCK MODE ACTIVE (Process-Local Fabric)</span>
        <button id="btn-reset" class="btn btn-outline" onclick="resetEstate()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
          Reset Estate
        </button>
        <button id="btn-run" class="btn btn-primary" onclick="runSelectedScenario()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Run Scenario
        </button>
      </div>
    </header>

    <!-- Main Grid -->
    <div class="main-grid">
      <!-- Sidebar / Scenario Selector -->
      <div class="sidebar">
        <div class="card">
          <div class="card-title">Select Demo Scenario</div>
          <div class="scenario-list">

            <div id="scen-1" class="scenario-item active" onclick="selectScenario(1)">
              <div class="scenario-header">
                <span class="scenario-id">SCENARIO 1</span>
                <span class="scenario-target">Windows (web-01)</span>
              </div>
              <div class="scenario-name">High-Severity Incident</div>
              <div class="scenario-desc">Standard containment, volatile RAM acquisition (WinPmem), SQL ledger hashing, and disk snapshotting.</div>
            </div>

            <div id="scen-2" class="scenario-item" onclick="selectScenario(2)">
              <div class="scenario-header">
                <span class="scenario-id">SCENARIO 2</span>
                <span class="scenario-target">Linux (db-02)</span>
              </div>
              <div class="scenario-name">Critical-Infra Bypass</div>
              <div class="scenario-desc">Target tagged Critical-Infrastructure: True. Network isolation safely bypassed; volatile memory & disk capture proceed.</div>
            </div>

            <div id="scen-3" class="scenario-item" onclick="selectScenario(3)">
              <div class="scenario-header">
                <span class="scenario-id">SCENARIO 3</span>
                <span class="scenario-target">Invalid (ghost-vm-99)</span>
              </div>
              <div class="scenario-name">Simulated Failure Handling</div>
              <div class="scenario-desc">Target resolution failure. Downstream execution cleanly aborted; reports actionable diagnostic without false success.</div>
            </div>

          </div>
        </div>

        <div class="card">
          <div class="card-title">Simulated Azure Estate</div>
          <div class="stat-row">
            <span class="stat-label">Compromised Sub:</span>
            <span class="stat-value">...0001 (rg-victims)</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Forensic Enclave Sub:</span>
            <span class="stat-value">...00e1 (rg-enclave)</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Simulated VMs:</span>
            <span class="stat-value" id="stat-vms">web-01, db-02</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Immutable Storage:</span>
            <span class="stat-value">reactenclave01 (Legal Hold)</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Ledger Chain:</span>
            <span class="stat-value" id="stat-ledger">SHA-256 Intact</span>
          </div>
        </div>

        <div class="card" style="font-size: 0.78rem; color: var(--text-muted); line-height: 1.5;">
          <div style="font-weight: 700; color: #ffffff; margin-bottom: 0.4rem;">Demo Verification Guarantee</div>
          No Azure REST API or Entra ID endpoints are contacted. All credentials and SAS tokens shown in evidence reports are automatically sanitized.
        </div>
      </div>

      <!-- Content Area -->
      <div class="content-panel">

        <div class="status-banner">
          <div class="status-left">
            <h2 id="current-title">Scenario 1: High-Severity Incident Response</h2>
            <p id="current-desc">Ready to execute. Click "Run Scenario" to dispatch automated containment and acquisition pipeline.</p>
          </div>
          <div id="scenario-status-badge">
            <span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-blue);">STANDBY</span>
          </div>
        </div>

        <div class="tabs">
          <button class="tab-btn active" onclick="switchTab('stages')">Workflow Stages</button>
          <button class="tab-btn" onclick="switchTab('evidence')">Sanitized Evidence Dossier</button>
          <button class="tab-btn" onclick="switchTab('ledger')">Cryptographic Custody Ledger</button>
        </div>

        <div id="tab-stages" class="stages-stepper">
          <!-- Populated dynamically via JS -->
          <div style="padding: 2rem; text-align: center; color: var(--text-dim);">
            Click <strong>"Run Scenario"</strong> above to trigger the simulated pipeline and inspect stage outcomes.
          </div>
        </div>

        <div id="tab-evidence" style="display: none;">
          <div class="card">
            <div class="card-title">Sanitized Case Evidence Record (Zero Bearer Secrets)</div>
            <pre id="evidence-json" class="stage-details">Select and run a scenario to inspect synthesized evidence metadata.</pre>
          </div>
        </div>

        <div id="tab-ledger" style="display: none;">
          <div class="card">
            <div class="card-title">Azure SQL Ledger Verification Table (Simulated Block-Chain Digest)</div>
            <pre id="ledger-json" class="stage-details">Loading ledger rows...</pre>
          </div>
        </div>

      </div>
    </div>

    <footer>
      Project REACT (Rapid Evidence Acquisition & Containment Toolkit) — Mid-Semester Prototype Demonstration.
      All resources and cryptographic digests are synthetic process-local simulations.
    </footer>
  </div>

  <script>
    let activeScenario = 1;
    let latestResult = null;

    function selectScenario(id) {
      activeScenario = id;
      document.querySelectorAll('.scenario-item').forEach(el => el.classList.remove('active'));
      const activeEl = document.getElementById('scen-' + id);
      if (activeEl) activeEl.classList.add('active');

      const titles = {
        1: "Scenario 1: High-Severity Incident Response",
        2: "Scenario 2: Critical Infrastructure Bypass",
        3: "Scenario 3: Simulated Failure Handling"
      };
      const descs = {
        1: "Standard containment, volatile RAM acquisition (WinPmem), SQL ledger hashing, and disk snapshotting.",
        2: "Target tagged Critical-Infrastructure: True. Isolation skipped; volatile RAM & disk snapshot proceed.",
        3: "Target resolution error. Downstream pipeline safely halted without false-positive evidence."
      };
      document.getElementById('current-title').textContent = titles[id];
      document.getElementById('current-desc').textContent = descs[id];
    }

    async function runSelectedScenario() {
      const btn = document.getElementById('btn-run');
      btn.disabled = true;
      btn.textContent = "Running Pipeline...";
      document.getElementById('scenario-status-badge').innerHTML =
        '<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: var(--accent-amber);">IN PROGRESS...</span>';

      try {
        const resp = await fetch('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: activeScenario })
        });
        const data = await resp.json();
        latestResult = data;
        renderResult(data);
        loadLedgerState();
      } catch (err) {
        alert("Failed to execute scenario: " + err);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Scenario';
      }
    }

    async function resetEstate() {
      const btn = document.getElementById('btn-reset');
      btn.disabled = true;
      try {
        const resp = await fetch('/api/reset', { method: 'POST' });
        const data = await resp.json();
        alert(data.message || "Simulated Azure estate reseeded successfully.");
        document.getElementById('tab-stages').innerHTML =
          '<div style="padding: 2rem; text-align: center; color: var(--text-dim);">Simulated estate reset to clean baseline. Click <strong>"Run Scenario"</strong> to begin.</div>';
        document.getElementById('evidence-json').textContent = "Estate reset. No recent scenario output.";
        document.getElementById('scenario-status-badge').innerHTML =
          '<span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-blue);">STANDBY</span>';
        loadLedgerState();
      } catch (err) {
        alert("Reset failed: " + err);
      } finally {
        btn.disabled = false;
      }
    }

    function renderResult(data) {
      const badgeContainer = document.getElementById('scenario-status-badge');
      if (data.status === 'succeeded') {
        badgeContainer.innerHTML = '<span class="badge badge-completed">PIPELINE SUCCEEDED</span>';
      } else if (data.status === 'partial') {
        badgeContainer.innerHTML = '<span class="badge badge-bypassed">PARTIAL EXECUTION</span>';
      } else {
        badgeContainer.innerHTML = '<span class="badge badge-failed">HALTED ON ERROR (SAFE)</span>';
      }

      const container = document.getElementById('tab-stages');
      container.innerHTML = '';

      data.stages.forEach((st, idx) => {
        const card = document.createElement('div');
        card.className = `stage-card ${st.status}`;
        card.innerHTML = `
          <div class="stage-top">
            <div class="stage-title">
              <span>Stage ${idx + 1}: ${st.name}</span>
            </div>
            <span class="stage-badge badge-${st.status}">${st.status}</span>
          </div>
          <div class="stage-summary">${st.summary}</div>
          <div class="stage-details">${JSON.stringify(st.details, null, 2)}</div>
        `;
        container.appendChild(card);
      });

      document.getElementById('evidence-json').textContent =
        JSON.stringify(data.sanitized_evidence, null, 2);
    }

    async function loadLedgerState() {
      try {
        const resp = await fetch('/api/state');
        const state = await resp.json();
        document.getElementById('stat-vms').textContent = (state.virtualMachines || []).join(', ');
        const intact = state.ledger && state.ledger.chainIntact;
        document.getElementById('stat-ledger').textContent = intact ? "SHA-256 Intact" : "Tampered";
        document.getElementById('ledger-json').textContent = JSON.stringify(state.ledger || {}, null, 2);
      } catch (e) {
        console.error("Could not load state:", e);
      }
    }

    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-stages').style.display = 'none';
      document.getElementById('tab-evidence').style.display = 'none';
      document.getElementById('tab-ledger').style.display = 'none';

      document.getElementById('tab-' + name).style.display = 'block';
      event.target.classList.add('active');
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadLedgerState();
    });
  </script>
</body>
</html>
"""


class DemoRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the local web dashboard."""

    def _json(self, status: int, data: Any):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        orch = get_orchestrator()
        path = self.path.split("?")[0].rstrip("/")

        if path in ("", "/"):
            self._html(200, HTML_PAGE)
        elif path == "/api/status":
            self._json(
                200,
                {
                    "simulationLabel": SIMULATION_LABEL,
                    "mockMode": True,
                    "prerequisites": orch.check_prerequisites(),
                },
            )
        elif path == "/api/state":
            self._json(200, orch.get_estate_state())
        else:
            self._json(404, {"error": f"Path not found: {self.path}"})

    def do_POST(self):
        orch = get_orchestrator()
        path = self.path.split("?")[0].rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_body.decode("utf-8")) if post_body else {}
        except ValueError:
            body = {}

        if path == "/api/reset":
            res = orch.reset_estate()
            self._json(200, res)
        elif path == "/api/run":
            scenario_id = body.get("scenario", 1)
            try:
                res = orch.run_scenario(scenario_id)
                self._json(200, res.to_dict())
            except Exception as exc:
                LOGGER.exception("Scenario execution error")
                self._json(500, {"error": str(exc), "simulationLabel": SIMULATION_LABEL})
        else:
            self._json(404, {"error": f"Path not found: {self.path}"})

    def log_message(self, format: str, *args: Any):
        # Suppress noise in stdout while running demo
        pass


def run_demo_server(host: str = "127.0.0.1", port: int = 8080):
    """Start local web dashboard server."""
    orch = get_orchestrator()
    orch.reset_estate()
    server = HTTPServer((host, port), DemoRequestHandler)
    print("=" * 70)
    print("  REACT DEMO DASHBOARD RUNNING")
    print(f"  URL: http://{host}:{port}")
    print(f"  Notice: {SIMULATION_LABEL}")
    print("  Press Ctrl+C to stop.")
    print("=" * 70)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo server...")
    finally:
        server.server_close()
