"""Controlled, target-neutral observation policy for injection capabilities.

The policy produces test values only. It does not perform HTTP requests and
does not conclude that a vulnerability exists.

The first values are benign controls. The remaining values are low-impact
syntax probes intended for explicitly authorised security labs/testing targets.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.dynamic_analysis.planning.models import ProbeCandidate


@dataclass(frozen=True)
class InjectionObservationPlan:
    """Values used by a differential injection observation."""

    baseline_value: str
    control_values: tuple[str, ...]
    syntax_values: tuple[str, ...]

    @property
    def test_values(self) -> tuple[str, ...]:
        return self.control_values + self.syntax_values


@dataclass(frozen=True)
class InjectionObservationPolicy:
    """Create conservative differential values without target-specific rules."""

    default_text_baseline: str = "egaa-baseline"
    default_numeric_baseline: str = "1"

    text_controls: tuple[str, ...] = (
        "egaa-control-a",
        "egaa-control-b",
    )
    numeric_controls: tuple[str, ...] = (
        "2",
        "3",
    )

    # Deliberately small syntax probes: enough to observe parser/error
    # differentials, but not destructive statements or data extraction.
    text_syntax_values: tuple[str, ...] = (
        "'",
        '"',
        "\\",
    )
    numeric_syntax_values: tuple[str, ...] = (
        "1'",
        '1"',
        "1\\",
    )

    def __post_init__(self) -> None:
        if not self.default_text_baseline:
            raise ValueError("default_text_baseline must not be empty.")
        if not self.default_numeric_baseline:
            raise ValueError("default_numeric_baseline must not be empty.")
        if not self.text_controls:
            raise ValueError("text_controls must not be empty.")
        if not self.numeric_controls:
            raise ValueError("numeric_controls must not be empty.")
        if not self.text_syntax_values:
            raise ValueError("text_syntax_values must not be empty.")
        if not self.numeric_syntax_values:
            raise ValueError("numeric_syntax_values must not be empty.")

    def plan(self, candidate: ProbeCandidate) -> InjectionObservationPlan:
        if not isinstance(candidate, ProbeCandidate):
            raise TypeError("candidate must be a ProbeCandidate.")

        numeric = self._is_numeric(candidate)
        baseline = (
            candidate.observed_value
            if candidate.observed_value is not None
            else (
                self.default_numeric_baseline
                if numeric
                else self.default_text_baseline
            )
        )

        controls = self.numeric_controls if numeric else self.text_controls
        syntax = (
            self.numeric_syntax_values
            if numeric
            else self.text_syntax_values
        )

        controls = self._without_baseline(controls, baseline)
        syntax = self._without_baseline(syntax, baseline)

        if not controls:
            raise ValueError(
                "observation policy must leave at least one control value."
            )
        if not syntax:
            raise ValueError(
                "observation policy must leave at least one syntax value."
            )

        return InjectionObservationPlan(
            baseline_value=baseline,
            control_values=controls,
            syntax_values=syntax,
        )

    @staticmethod
    def _without_baseline(
        values: tuple[str, ...],
        baseline: str,
    ) -> tuple[str, ...]:
        return tuple(value for value in values if value != baseline)

    @staticmethod
    def _is_numeric(candidate: ProbeCandidate) -> bool:
        return (candidate.input_type or "").lower() in {"number", "range"}
