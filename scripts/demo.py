#!/usr/bin/env python3
"""REACT — Mid-Semester Incident Response & Forensic Prototype Demonstration Launcher.

Usage:
    python scripts/demo.py                   # Launch interactive terminal demo runner
    python scripts/demo.py --scenario 1      # Run Scenario 1 (High-Severity Response)
    python scripts/demo.py --scenario 2      # Run Scenario 2 (Critical-Infra Bypass)
    python scripts/demo.py --scenario 3      # Run Scenario 3 (Simulated Failure)
    python scripts/demo.py --scenario all    # Run all 3 scenarios in sequence
    python scripts/demo.py --check           # Check local environment prerequisites
    python scripts/demo.py --reset           # Reset in-memory simulated Azure estate
    python scripts/demo.py --web             # Launch interactive browser dashboard
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from src.demo import SIMULATION_LABEL, get_orchestrator  # noqa: E402
from src.demo.server import run_demo_server  # noqa: E402

# ANSI Color codes for rich terminal display
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{YELLOW}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{YELLOW}{BOLD}  NOTICE: {SIMULATION_LABEL}{RESET}")
    print(f"{YELLOW}{BOLD}" + "=" * 78 + f"{RESET}\n")


def print_header(title: str):
    print(f"\n{CYAN}{BOLD}--- {title} ---{RESET}\n")


def run_checks() -> bool:
    print_banner()
    print_header("Prerequisites Verification")
    orch = get_orchestrator()
    res = orch.check_prerequisites()

    for check in res["checks"].values():
        symbol = f"{GREEN}[PASS]{RESET}" if check["passed"] else f"{RED}[FAIL]{RESET}"
        print(f"  {symbol} {BOLD}{check['name']}{RESET}")
        print(f"         {DIM}{check['detail']}{RESET}")

    status_str = f"{GREEN}{BOLD}ALL CHECKS PASSED{RESET}" if res["allPassed"] else f"{RED}{BOLD}CHECK FAILURES DETECTED{RESET}"
    print(f"\nResult: {status_str}\n")
    return res["allPassed"]


def run_reset():
    print_banner()
    orch = get_orchestrator()
    res = orch.reset_estate()
    print(f"{GREEN}{BOLD}Estate Reset Successful!{RESET}")
    print(f"  Message: {res['message']}")
    print(f"  Simulated VMs in rg-victims: {', '.join(res['vms'])}\n")


def print_scenario_result(result):
    print_banner()
    print(f"{CYAN}{BOLD}Scenario {result.scenario_id}: {result.title}{RESET}")
    print(f"{DIM}{result.description}{RESET}\n")
    print(f"  Incident ID : {BOLD}{result.incident_id}{RESET}")
    print(f"  Target VM   : {BOLD}{result.target_vm.split('/')[-1]}{RESET}")

    status_color = GREEN if result.status == "succeeded" else (YELLOW if result.status == "partial" else RED)
    print(f"  Outcome     : {status_color}{BOLD}{result.status.upper()}{RESET}\n")

    print(f"{BOLD}Execution Stages:{RESET}")
    print("-" * 78)
    for idx, stage in enumerate(result.stages, 1):
        if stage.status == "completed":
            badge = f"{GREEN}[COMPLETED]{RESET}"
        elif stage.status == "bypassed":
            badge = f"{YELLOW}[BYPASSED]{RESET}"
        elif stage.status == "failed":
            badge = f"{RED}[FAILED]{RESET}"
        else:
            badge = f"{DIM}[SKIPPED]{RESET}"

        print(f"  {idx}. {badge} {BOLD}{stage.name}{RESET}")
        print(f"     Summary : {stage.summary}")
        if stage.details:
            details_str = json.dumps(stage.details, indent=2)
            indented = "\n".join("       " + line for line in details_str.splitlines())
            print(f"     Details :\n{DIM}{indented}{RESET}")
        print()

    print("-" * 78)
    print(f"{BOLD}Sanitized Evidence Dossier (Zero Exposed Secrets):{RESET}")
    dossier_str = json.dumps(result.sanitized_evidence, indent=2)
    print(f"{DIM}" + "\n".join("  " + line for line in dossier_str.splitlines()) + f"{RESET}\n")


def interactive_menu():
    orch = get_orchestrator()
    while True:
        print_banner()
        print(f"{BOLD}REACT Mid-Semester Prototype — Interactive Runner{RESET}")
        print("Select an option:")
        print(f"  {CYAN}1{RESET}) Run Scenario 1: High-Severity Response (Windows web-01)")
        print(f"  {CYAN}2{RESET}) Run Scenario 2: Critical-Infra Bypass (Linux db-02)")
        print(f"  {CYAN}3{RESET}) Run Scenario 3: Simulated Failure Handling (ghost-vm-99)")
        print(f"  {CYAN}4{RESET}) Run ALL 3 Scenarios sequentially")
        print(f"  {CYAN}5{RESET}) Launch Interactive Web Dashboard (http://127.0.0.1:8080)")
        print(f"  {CYAN}6{RESET}) Check System Prerequisites")
        print(f"  {CYAN}7{RESET}) Reset Simulated Azure Estate")
        print(f"  {CYAN}q{RESET}) Quit")
        print()

        try:
            choice = input(f"{BOLD}Enter selection [1-7, q]: {RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            orch.reset_estate()
            res = orch.run_scenario(1)
            print_scenario_result(res)
        elif choice == "2":
            orch.reset_estate()
            res = orch.run_scenario(2)
            print_scenario_result(res)
        elif choice == "3":
            orch.reset_estate()
            res = orch.run_scenario(3)
            print_scenario_result(res)
        elif choice == "4":
            for sid in (1, 2, 3):
                orch.reset_estate()
                res = orch.run_scenario(sid)
                print_scenario_result(res)
        elif choice == "5":
            run_demo_server()
        elif choice == "6":
            run_checks()
        elif choice == "7":
            run_reset()
        elif choice in ("q", "quit", "exit"):
            print("Goodbye.")
            break
        else:
            print(f"{RED}Invalid option. Please enter 1-7 or q.{RESET}")

        try:
            input(f"\n{DIM}Press Enter to return to menu...{RESET}")
        except (KeyboardInterrupt, EOFError):
            break


def main():
    parser = argparse.ArgumentParser(
        description="REACT Mid-Semester Incident Response Prototype Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=["1", "2", "3", "all"],
        help="Run specific scenario or all scenarios non-interactively",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run prerequisite and mock safety verification",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset simulated in-memory Azure estate",
    )
    parser.add_argument(
        "--web",
        "--ui",
        action="store_true",
        help="Start local interactive browser dashboard",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for local web dashboard (default: 8080)",
    )

    args = parser.parse_args()

    orch = get_orchestrator()

    if args.check:
        passed = run_checks()
        sys.exit(0 if passed else 1)
    elif args.reset:
        run_reset()
        sys.exit(0)
    elif args.web:
        run_demo_server(port=args.port)
        sys.exit(0)
    elif args.scenario:
        if args.scenario == "all":
            for sid in (1, 2, 3):
                orch.reset_estate()
                res = orch.run_scenario(sid)
                print_scenario_result(res)
        else:
            orch.reset_estate()
            res = orch.run_scenario(int(args.scenario))
            print_scenario_result(res)
        sys.exit(0)
    else:
        # Default to interactive runner if stdin is a tty, else print help
        if sys.stdin.isatty():
            interactive_menu()
        else:
            # Non-interactive without args -> run checks and scenario 1
            run_checks()
            orch.reset_estate()
            res = orch.run_scenario(1)
            print_scenario_result(res)


if __name__ == "__main__":
    main()
