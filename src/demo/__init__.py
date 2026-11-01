"""REACT local demonstration package.

Provides offline scenario orchestration, estate management, and interactive
demonstration capabilities for the mid-semester prototype.
"""

from .orchestrator import (
    SIMULATION_LABEL,
    DemoOrchestrator,
    ScenarioResult,
    get_orchestrator,
)

__all__ = [
    "SIMULATION_LABEL",
    "DemoOrchestrator",
    "ScenarioResult",
    "get_orchestrator",
]
