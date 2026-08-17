from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from harness.core.storage import canonical_hash

from .metrics import BenchmarkRunRecord, build_run_record
from .models import BenchmarkRunSpec, EvaluationMode, IndependentAdjudication, RawRunOutcome
from .runner import BenchmarkPlan


def _require_sha256(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")
    return value


@dataclass(frozen=True)
class BenchmarkExecutorDescriptor:
    executor_id: str
    model_id: str
    model_revision: str
    controller_revision: str
    tool_inventory: tuple[str, ...]
    sandbox_id: str
    oracle_policy_id: str
    web_search_enabled: bool
    external_retrieval_enabled: bool
    general_internet_egress_enabled: bool
    challenge_transport_only: bool

    def __post_init__(self) -> None:
        for field in (
            "executor_id",
            "model_id",
            "model_revision",
            "controller_revision",
            "sandbox_id",
            "oracle_policy_id",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a non-empty string")
        if not isinstance(self.tool_inventory, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.tool_inventory
        ):
            raise ValueError("tool_inventory must be an immutable tuple of non-empty strings")
        if len(set(self.tool_inventory)) != len(self.tool_inventory):
            raise ValueError("tool_inventory must be unique")
        for field in (
            "web_search_enabled",
            "external_retrieval_enabled",
            "general_internet_egress_enabled",
            "challenge_transport_only",
        ):
            if not isinstance(getattr(self, field), bool):
                raise ValueError(f"{field} must be boolean")

    def fingerprint(self) -> str:
        return canonical_hash({
            "executor_id": self.executor_id,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "controller_revision": self.controller_revision,
            "tool_inventory": sorted(self.tool_inventory),
            "sandbox_id": self.sandbox_id,
            "oracle_policy_id": self.oracle_policy_id,
            "web_search_enabled": self.web_search_enabled,
            "external_retrieval_enabled": self.external_retrieval_enabled,
            "general_internet_egress_enabled": self.general_internet_egress_enabled,
            "challenge_transport_only": self.challenge_transport_only,
        })


@dataclass(frozen=True)
class ExecutionBoundaryAttestation:
    issuer_id: str
    evidence_sha256: str
    executor_fingerprint: str
    sandbox_id: str
    web_search_blocked: bool
    external_retrieval_blocked: bool
    general_internet_egress_blocked: bool
    challenge_transport_scoped: bool

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise ValueError("attestation issuer_id must be a non-empty string")
        _require_sha256(self.evidence_sha256, field="attestation evidence_sha256")
        _require_sha256(self.executor_fingerprint, field="attestation executor_fingerprint")
        if not isinstance(self.sandbox_id, str) or not self.sandbox_id.strip():
            raise ValueError("attestation sandbox_id must be a non-empty string")
        for field in (
            "web_search_blocked",
            "external_retrieval_blocked",
            "general_internet_egress_blocked",
            "challenge_transport_scoped",
        ):
            if not isinstance(getattr(self, field), bool):
                raise ValueError(f"attestation {field} must be boolean")


@dataclass(frozen=True)
class ExecutorRunReceipt:
    executor_id: str
    run_evidence_sha256: str
    outcome: RawRunOutcome

    def __post_init__(self) -> None:
        if not isinstance(self.executor_id, str) or not self.executor_id.strip():
            raise ValueError("executor receipt executor_id must be a non-empty string")
        _require_sha256(self.run_evidence_sha256, field="run_evidence_sha256")
        if not isinstance(self.outcome, RawRunOutcome):
            raise ValueError("executor receipt outcome must be RawRunOutcome")


class BenchmarkRunExecutor(Protocol):
    def descriptor(self) -> BenchmarkExecutorDescriptor: ...
    def execute(self, spec: BenchmarkRunSpec) -> ExecutorRunReceipt: ...


class IndependentAdjudicator(Protocol):
    def adjudicate(
        self,
        spec: BenchmarkRunSpec,
        outcome: RawRunOutcome,
        *,
        run_evidence_sha256: str,
    ) -> IndependentAdjudication: ...


def _require_spec_in_plan(plan: BenchmarkPlan, spec: BenchmarkRunSpec) -> None:
    planned = {item.run_id(): item for item in plan.runs}
    expected = planned.get(spec.run_id())
    if expected is None:
        raise ValueError("benchmark run spec is not present in the frozen plan")
    if expected != spec:
        raise ValueError("benchmark run spec differs from the exact frozen plan entry")


def _validate_executor_contract(spec: BenchmarkRunSpec, descriptor: BenchmarkExecutorDescriptor) -> None:
    experiment = spec.experiment
    expected_tools = tuple(sorted(experiment.tool_inventory))
    observed_tools = tuple(sorted(descriptor.tool_inventory))
    mismatches = []
    for field in (
        "model_id",
        "model_revision",
        "controller_revision",
        "sandbox_id",
        "oracle_policy_id",
    ):
        if getattr(descriptor, field) != getattr(experiment, field):
            mismatches.append(field)
    if observed_tools != expected_tools:
        mismatches.append("tool_inventory")
    if mismatches:
        raise ValueError("executor differs from experiment contract: " + ", ".join(mismatches))


def _validate_boundary(
    spec: BenchmarkRunSpec,
    descriptor: BenchmarkExecutorDescriptor,
    attestation: ExecutionBoundaryAttestation,
) -> None:
    if attestation.executor_fingerprint != descriptor.fingerprint():
        raise ValueError("execution-boundary attestation is for a different executor descriptor")
    if attestation.sandbox_id != descriptor.sandbox_id:
        raise ValueError("execution-boundary attestation sandbox differs from executor")

    if descriptor.web_search_enabled == attestation.web_search_blocked:
        raise ValueError("executor web-search descriptor conflicts with boundary attestation")
    if descriptor.external_retrieval_enabled == attestation.external_retrieval_blocked:
        raise ValueError("executor retrieval descriptor conflicts with boundary attestation")
    if descriptor.general_internet_egress_enabled == attestation.general_internet_egress_blocked:
        raise ValueError("executor internet-egress descriptor conflicts with boundary attestation")
    if descriptor.challenge_transport_only != attestation.challenge_transport_scoped:
        raise ValueError("executor challenge-transport scope conflicts with boundary attestation")

    if spec.experiment.mode is EvaluationMode.RESEARCH:
        if descriptor.web_search_enabled or not attestation.web_search_blocked:
            raise ValueError("research executor requires physically attested web-search blocking")
        if descriptor.external_retrieval_enabled or not attestation.external_retrieval_blocked:
            raise ValueError("research executor requires physically attested external-retrieval blocking")
        if descriptor.general_internet_egress_enabled or not attestation.general_internet_egress_blocked:
            raise ValueError("research executor requires physically attested general-internet egress blocking")
        if not descriptor.challenge_transport_only or not attestation.challenge_transport_scoped:
            raise ValueError("research executor network access must be scoped to challenge transport")


def execute_planned_run(
    *,
    plan: BenchmarkPlan,
    spec: BenchmarkRunSpec,
    executor: BenchmarkRunExecutor,
    boundary_attestation: ExecutionBoundaryAttestation,
    adjudicator: IndependentAdjudicator,
) -> BenchmarkRunRecord:
    """Execute one exact planned run only after contract/boundary validation.

    The executor is still responsible for actually enforcing its sandbox and
    producing the attestation evidence. This function prevents execution when
    the supplied descriptor/attestation does not prove the required boundary.
    Final success remains independent adjudication, never executor self-report.
    """
    _require_spec_in_plan(plan, spec)
    descriptor = executor.descriptor()
    if not isinstance(descriptor, BenchmarkExecutorDescriptor):
        raise ValueError("executor descriptor must be BenchmarkExecutorDescriptor")
    _validate_executor_contract(spec, descriptor)
    _validate_boundary(spec, descriptor, boundary_attestation)

    receipt = executor.execute(spec)
    if not isinstance(receipt, ExecutorRunReceipt):
        raise ValueError("executor must return ExecutorRunReceipt")
    if receipt.executor_id != descriptor.executor_id:
        raise ValueError("executor receipt identity differs from validated executor")

    adjudication = adjudicator.adjudicate(
        spec,
        receipt.outcome,
        run_evidence_sha256=receipt.run_evidence_sha256,
    )
    if not isinstance(adjudication, IndependentAdjudication):
        raise ValueError("adjudicator must return IndependentAdjudication")
    return build_run_record(spec, receipt.outcome, adjudication)
