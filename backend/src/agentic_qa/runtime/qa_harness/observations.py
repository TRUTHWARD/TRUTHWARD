# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterable

from pydantic import ValidationError

from agentic_qa.runtime.qa_harness.contracts import Observation


def validate_service_observations(value: object, *, intent_id: str) -> list[Observation]:
    candidates: Iterable[object]
    if isinstance(value, (list, tuple)):
        candidates = value
    else:
        candidates = [value]
    observations: list[Observation] = []
    try:
        for candidate in candidates:
            observation = (
                candidate
                if isinstance(candidate, Observation)
                else Observation.model_validate(candidate)
            )
            if observation.intentId is not None and observation.intentId != intent_id:
                raise ValueError("Observation intentId does not match requested Skill Intent")
            observations.append(observation)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ValueError("Service returned an invalid Observation") from exc
    if not observations:
        raise ValueError("Service returned no Observation")
    return observations


__all__ = ["Observation", "validate_service_observations"]
