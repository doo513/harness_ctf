from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True)
class PlaybookQuestion:
    """Advisory information target; never an executable action or truth source."""

    question_id: str
    question: str
    expected_information: str
    priority: str
    rationale: str
    suggested_capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("question_id", "question", "expected_information", "priority", "rationale"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if self.priority not in {"high", "medium", "low"}:
            raise ValueError("playbook priority must be high, medium, or low")
        if not isinstance(self.suggested_capabilities, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.suggested_capabilities
        ):
            raise ValueError("suggested_capabilities must be an immutable tuple of non-empty strings")

    def descriptor(self, *, available_tools: set[str]) -> dict:
        available = [name for name in self.suggested_capabilities if name in available_tools]
        missing = [name for name in self.suggested_capabilities if name not in available_tools]
        return {
            "id": self.question_id,
            "question": self.question,
            "expected_information": self.expected_information,
            "priority": self.priority,
            "rationale": self.rationale,
            "suggested_capabilities": list(self.suggested_capabilities),
            "available_capabilities": available,
            "missing_capabilities": missing,
        }


@dataclass(frozen=True)
class PlaybookStage:
    stage_id: str
    goal: str
    questions: tuple[PlaybookQuestion, ...]
    progress_signals: tuple[str, ...] = ()
    pivot_conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise ValueError("stage_id must be non-empty")
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise ValueError("stage goal must be non-empty")
        if not isinstance(self.questions, tuple) or not self.questions:
            raise ValueError("playbook stage requires at least one question")
        if any(not isinstance(item, PlaybookQuestion) for item in self.questions):
            raise ValueError("questions must contain PlaybookQuestion values")

    def descriptor(self, *, available_tools: set[str]) -> dict:
        return {
            "stage": self.stage_id,
            "goal": self.goal,
            "questions": [q.descriptor(available_tools=available_tools) for q in self.questions],
            "progress_signals": list(self.progress_signals),
            "pivot_conditions": list(self.pivot_conditions),
        }


class DomainPlaybook(Protocol):
    """A domain-specific advisory policy projection.

    A playbook may prioritize questions and pivots, but it may not execute tools,
    write facts, verify claims, or establish completion.
    """

    domain: str
    revision: str

    def snapshot(
        self,
        *,
        verified_fact_keys: Sequence[str],
        hypothesis_statuses: Sequence[str],
        available_tools: Sequence[str],
        completed: bool,
    ) -> dict: ...
