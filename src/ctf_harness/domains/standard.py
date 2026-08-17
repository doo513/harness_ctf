from __future__ import annotations

from collections.abc import Sequence

from .base import PlaybookQuestion, PlaybookStage


class _StaticPlaybook:
    domain = ""
    revision = ""
    stage: PlaybookStage

    def snapshot(self, *, verified_fact_keys: Sequence[str], hypothesis_statuses: Sequence[str], available_tools: Sequence[str], completed: bool) -> dict:
        counts = {name: 0 for name in ("open", "supported", "refuted", "proved")}
        for status in hypothesis_statuses:
            if status in counts:
                counts[status] += 1
        return {
            "schema_version": "ctf-domain-playbook-v1",
            "domain": self.domain,
            "revision": self.revision,
            "authority": "advisory_policy",
            "instruction_authority": "advisory",
            "truth_authority": "none",
            "completion_authority": "none",
            "hard_sequence": False,
            "current": self.stage.descriptor(available_tools=set(available_tools)),
            "tactical_hypothesis_counts": counts,
        }


class ReversePlaybook(_StaticPlaybook):
    domain = "reverse"
    revision = "reverse-playbook-v1"
    stage = PlaybookStage(
        "surface",
        "Reduce uncertainty about file format, architecture, strings, validation paths, and data flow before deep decompilation.",
        (
            PlaybookQuestion("reverse.profile", "What file/architecture and symbol/stripping properties constrain analysis?", "binary_profile", "high", "Selects useful static/dynamic analysis capabilities.", ("domain_recon", "pwn_recon")),
            PlaybookQuestion("reverse.validation", "Which function or data path appears to transform or validate candidate input?", "validation_path_localization", "high", "Narrows decompilation to the code most likely to determine the answer.", ("analysis_exec", "decompile_function")),
        ),
        ("entry/validation path localized",),
        ("packed binary", "non-native architecture", "self-modifying/runtime-generated logic"),
    )


class CryptoPlaybook(_StaticPlaybook):
    domain = "crypto"
    revision = "crypto-playbook-v1"
    stage = PlaybookStage(
        "surface",
        "Identify the cryptosystem, parameters, reuse/structure, and attackable assumptions before attempting expensive search.",
        (
            PlaybookQuestion("crypto.parameters", "What primitive and exact parameters are present, and which values are reused or unusually small/structured?", "cryptosystem_parameter_inventory", "high", "Most crypto challenge search space collapses after identifying the violated assumption.", ("domain_recon", "analysis_exec")),
            PlaybookQuestion("crypto.attack", "Which single hypothesis can be confirmed or refuted with the cheapest deterministic computation?", "confirm_or_refute_crypto_assumption", "high", "Avoids blind brute force and unsupported algebraic guesses.", ("analysis_exec",)),
        ),
        ("parameter set extracted", "attack assumption supported"),
        ("missing parameters", "incorrect primitive classification", "computation exceeds budget"),
    )


class WebPlaybook(_StaticPlaybook):
    domain = "web"
    revision = "web-playbook-v1"
    stage = PlaybookStage(
        "surface",
        "Map declared challenge origin, routes, authentication boundaries, inputs, and server-side sinks without sharing platform credentials.",
        (
            PlaybookQuestion("web.routes", "Which routes/endpoints and methods are reachable on the admitted challenge origin?", "route_surface_inventory", "high", "Route and auth boundaries determine the useful test space.", ("domain_recon", "scoped_http")),
            PlaybookQuestion("web.inputs", "Which user-controlled fields reach security-sensitive server-side operations?", "input_to_sink_mapping", "high", "Separates exploitable server behavior from client-only observations.", ("domain_recon", "scoped_http", "analysis_exec")),
        ),
        ("route/auth/input surface mapped",),
        ("origin not admitted", "browser-only flow", "authentication required"),
    )


class ForensicsPlaybook(_StaticPlaybook):
    domain = "forensics"
    revision = "forensics-playbook-v1"
    stage = PlaybookStage(
        "surface",
        "Identify container/file signatures, metadata, embedded objects, and timelines before destructive extraction.",
        (
            PlaybookQuestion("forensics.profile", "What file/container signatures and metadata identify the highest-value extraction path?", "artifact_structure_inventory", "high", "Structured extraction reduces blind carving and context volume.", ("domain_recon", "analysis_exec")),
        ),
        ("embedded structure localized",),
        ("nested archive", "corrupt container", "large extraction ratio"),
    )


class MiscPlaybook(_StaticPlaybook):
    domain = "misc"
    revision = "misc-playbook-v1"
    stage = PlaybookStage(
        "surface",
        "Classify the artifact/problem by observable structure and choose the smallest capability set that reduces uncertainty.",
        (
            PlaybookQuestion("misc.classify", "Which observable format/protocol/encoding most strongly constrains the next action?", "problem_structure_classification", "high", "Misc problems benefit from delaying commitment until the dominant structure is identified.", ("domain_recon", "analysis_exec")),
        ),
        ("dominant structure identified",),
        ("mixed-domain evidence", "requires specialized runtime"),
    )
