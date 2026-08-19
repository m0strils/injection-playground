"""
attacks/ — one documented attack per file, each paired with the defense that
stops it. Every case is a BENIGN, LOCAL demonstration: no real secrets, no real
exploitation, nothing external is targeted. The value of the lab is the defense.

Each attack module defines a `CASE` (an AttackCase). `succeeded(result)` returns
True when the attack achieved its (harmless, simulated) goal — so the runner can
assert it lands on the vulnerable app and is stopped on the defended one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class AttackCase:
    id: str
    name: str
    owasp: str            # OWASP LLM Top 10 id
    exploits: str         # what weakness it abuses
    payload: str          # the user question sent to the assistant
    defense: str          # the layer that stops it
    expected_undefended: str
    expected_defended: str
    succeeded: Callable    # (Result) -> bool : did the attack reach its goal?


def load_cases() -> list[AttackCase]:
    from attacks import (
        attack_01_direct_injection,
        attack_02_indirect_rag_poisoning,
        attack_03_secret_exfiltration,
        attack_04_insecure_output,
    )
    return [
        attack_01_direct_injection.CASE,
        attack_02_indirect_rag_poisoning.CASE,
        attack_03_secret_exfiltration.CASE,
        attack_04_insecure_output.CASE,
    ]
