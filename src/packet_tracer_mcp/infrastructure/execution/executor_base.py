"""
Abstract basis for topology executors.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from ...domain.models.plans import TopologyPlan


class ExecutorBase(ABC):
    """Interface for executing a plan in Packet Tracer."""

    @abstractmethod
    def execute(self, plan: TopologyPlan, project_name: str | None = None) -> dict:
        """Execute a plan and return results."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the executor is available."""
        ...
