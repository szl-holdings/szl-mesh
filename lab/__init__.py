"""Finite, read-only convergence laboratory for SZL Mesh."""

from .app import app, create_app
from .simulator import SCENARIOS, SimulationError, simulate_scenario

__all__ = ["SCENARIOS", "SimulationError", "app", "create_app", "simulate_scenario"]
