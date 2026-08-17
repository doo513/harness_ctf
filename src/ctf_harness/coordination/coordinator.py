from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol, Sequence

from .evidence_bus import EvidenceBus, FindingEnvelope


class AgentWorker(Protocol):
    worker_id: str

    def run_round(self, *, round_index: int, shared_context: dict[str, Any]) -> Sequence[FindingEnvelope]: ...


@dataclass(frozen=True)
class CoordinationRoundReceipt:
    round_index: int
    worker_ids: tuple[str, ...]
    findings_published: int
    bus_snapshot: dict[str, Any]


class MultiAgentCoordinator:
    """Optional parallel finding coordinator with no fact/completion authority.

    Workers do not receive a mutable HarnessState. They receive an immutable
    snapshot supplied by the caller plus the provenance-aware EvidenceBus view.
    Any actual tool execution or state mutation remains outside this coordinator
    and must go through the normal Harness runtime.
    """

    def __init__(
        self,
        *,
        workers: Sequence[AgentWorker],
        evidence_bus: EvidenceBus,
        max_workers: int | None = None,
    ):
        if not isinstance(workers, Sequence) or not workers:
            raise ValueError("multi-agent coordinator requires at least one worker")
        ids = []
        for worker in workers:
            worker_id = getattr(worker, "worker_id", None)
            if not isinstance(worker_id, str) or not worker_id.strip():
                raise ValueError("every worker must expose a non-empty worker_id")
            if not callable(getattr(worker, "run_round", None)):
                raise ValueError("every worker must expose run_round()")
            ids.append(worker_id)
        if len(set(ids)) != len(ids):
            raise ValueError("worker IDs must be unique")
        if not isinstance(evidence_bus, EvidenceBus):
            raise ValueError("evidence_bus must be EvidenceBus")
        if max_workers is not None and (
            not isinstance(max_workers, int) or isinstance(max_workers, bool) or max_workers <= 0
        ):
            raise ValueError("max_workers must be a positive integer when provided")
        self.workers = tuple(workers)
        self.evidence_bus = evidence_bus
        self.max_workers = max_workers or len(self.workers)
        self._round_index = 0

    def run_round(self, *, shared_context: dict[str, Any]) -> CoordinationRoundReceipt:
        if not isinstance(shared_context, dict):
            raise ValueError("shared_context must be a dict")
        round_index = self._round_index
        bus_before = self.evidence_bus.snapshot()
        worker_context = {
            "schema_version": "ctf-multi-agent-round-context-v1",
            "round_index": round_index,
            "shared": dict(shared_context),
            "evidence_bus": bus_before,
            "mutable_harness_state_available": False,
            "truth_authority": "none",
        }

        def invoke(worker: AgentWorker):
            findings = worker.run_round(round_index=round_index, shared_context=worker_context)
            if not isinstance(findings, Sequence):
                raise ValueError(f"worker {worker.worker_id} returned a non-sequence")
            rendered = tuple(findings)
            for finding in rendered:
                if not isinstance(finding, FindingEnvelope):
                    raise ValueError(f"worker {worker.worker_id} returned non-FindingEnvelope")
                if finding.source_agent != worker.worker_id:
                    raise ValueError("finding source_agent must match worker identity")
            return worker.worker_id, rendered

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.workers))) as pool:
            results = list(pool.map(invoke, self.workers))

        # Deterministic publication order makes the shared trace reproducible
        # even though worker computation may happen concurrently.
        published = 0
        for worker_id, findings in sorted(results, key=lambda item: item[0]):
            for finding in sorted(findings, key=lambda item: item.finding_id):
                self.evidence_bus.publish(finding)
                published += 1

        self._round_index += 1
        return CoordinationRoundReceipt(
            round_index=round_index,
            worker_ids=tuple(sorted(worker.worker_id for worker in self.workers)),
            findings_published=published,
            bus_snapshot=self.evidence_bus.snapshot(),
        )

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-multi-agent-coordinator-v1",
            "worker_ids": sorted(worker.worker_id for worker in self.workers),
            "max_workers": self.max_workers,
            "fact_write_authority": "none",
            "tool_execution_authority": "none",
            "completion_authority": "none",
            "shared_state": "evidence_bus_snapshot_only",
        }
