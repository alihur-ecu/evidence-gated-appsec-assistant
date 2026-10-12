"""Capability routing for independent finding verification.

This module decides *whether* a canonical Finding can enter an available
verification path. It deliberately does not collect evidence and does not
make a security decision.

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides

Routing is capability-based rather than a chain of vulnerability-specific
branches. New vulnerability families can therefore be preserved by the
Finding model even when no verifier has been registered for them yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from app.models.finding import Finding, FindingStatus, FindingType


class VerificationReadiness(str, Enum):
    """Whether a finding can enter independent verification now."""

    READY = "READY"
    CONTEXT_REQUIRED = "CONTEXT_REQUIRED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"


class VerificationMode(str, Enum):
    """Broad evidence source required by a verification capability."""

    RUNTIME = "RUNTIME"
    STATIC = "STATIC"


@dataclass(frozen=True)
class VerificationCapability:
    """Declarative description of one independent verification capability.

    ``finding_types`` identifies the normalised vulnerability families that
    the capability understands. The router itself does not need to know
    those families.

    ``required_fields`` describes the Finding context that must be present
    before execution can start. A future capability can therefore require
    source_file/line_number instead of endpoint/method/parameter without a
    router rewrite.
    """

    capability_id: str
    verifier_id: str
    mode: VerificationMode
    finding_types: frozenset[FindingType]
    required_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.capability_id.strip():
            raise ValueError(
                "capability_id must be a non-empty string."
            )

        if not self.verifier_id.strip():
            raise ValueError(
                "verifier_id must be a non-empty string."
            )

        if not self.finding_types:
            raise ValueError(
                "finding_types must contain at least one type."
            )


@dataclass(frozen=True)
class VerificationRoute:
    """Routing result consumed by service/web layers."""

    readiness: VerificationReadiness
    finding_type: FindingType
    raw_finding_type: str | None

    capability_id: str | None = None
    verifier_id: str | None = None
    mode: VerificationMode | None = None

    missing_fields: tuple[str, ...] = ()
    reason: str = ""

    @property
    def can_verify(self) -> bool:
        return (
            self.readiness
            is VerificationReadiness.READY
        )

    def to_dict(self) -> dict:
        return {
            "readiness":
                self.readiness.value,

            "can_verify":
                self.can_verify,

            "finding_type":
                self.finding_type.value,

            "raw_finding_type":
                self.raw_finding_type,

            "capability_id":
                self.capability_id,

            "verifier_id":
                self.verifier_id,

            "mode":
                (
                    self.mode.value
                    if self.mode
                    else None
                ),

            "missing_fields":
                list(self.missing_fields),

            "reason":
                self.reason,
        }


# ----------------------------------------------------------------------
# CURRENT PRODUCTION CAPABILITIES
# ----------------------------------------------------------------------
#
# This is intentionally declarative.
#
# SQL Injection currently has a real, already-tested deterministic
# differential runtime verifier.
#
# XSS and future vulnerability families remain perfectly valid Findings,
# but they are not advertised as independently verifiable until a real
# verification capability is implemented and registered.
# ----------------------------------------------------------------------

INJECTION_DIFFERENTIAL = VerificationCapability(
    capability_id="INJECTION_DIFFERENTIAL",
    verifier_id="injection_differential",
    mode=VerificationMode.RUNTIME,

    finding_types=frozenset({
        FindingType.SQL_INJECTION,
    }),

    required_fields=(
        "endpoint",
        "method",
        "parameter",
    ),
)


STATIC_SQL_INJECTION_SOURCE = VerificationCapability(
    capability_id="STATIC_SQL_INJECTION_SOURCE",
    verifier_id="static_sql_injection_source",
    mode=VerificationMode.STATIC,
    finding_types=frozenset({
        FindingType.SQL_INJECTION,
    }),
    required_fields=(),
)


STATIC_XSS_SOURCE_OBSERVATION = VerificationCapability(
    capability_id="STATIC_XSS_SOURCE_OBSERVATION",
    verifier_id="static_xss_source_observation",
    mode=VerificationMode.STATIC,
    finding_types=frozenset({FindingType.XSS}),
    required_fields=(),
)


DEFAULT_VERIFICATION_CAPABILITIES = (
    INJECTION_DIFFERENTIAL,
    STATIC_SQL_INJECTION_SOURCE,
    STATIC_XSS_SOURCE_OBSERVATION,
)


class VerificationRouter:
    """Resolve Findings to registered verification capabilities.

    The router contains no SQL/XSS/etc. branching.

    Supporting another vulnerability is an additive operation:

        1. implement its verifier/probe
        2. declare a VerificationCapability
        3. register it
        4. add tests

    The central router does not need to be rewritten.
    """

    def __init__(
        self,
        capabilities: Iterable[
            VerificationCapability
        ] = DEFAULT_VERIFICATION_CAPABILITIES,
    ) -> None:

        self._capabilities: dict[
            str,
            VerificationCapability,
        ] = {}

        for capability in capabilities:
            self.register(
                capability
            )

    def register(
        self,
        capability: VerificationCapability,
    ) -> None:

        if not isinstance(
            capability,
            VerificationCapability,
        ):
            raise TypeError(
                "capability must be a "
                "VerificationCapability."
            )

        if (
            capability.capability_id
            in self._capabilities
        ):
            raise ValueError(
                "capability_id already registered: "
                f"{capability.capability_id}"
            )

        self._capabilities[
            capability.capability_id
        ] = capability

    def route(
        self,
        finding: Finding,
    ) -> VerificationRoute:

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "finding must be a Finding."
            )

        # --------------------------------------------------------------
        # Lifecycle gate
        # --------------------------------------------------------------

        if (
            finding.status
            is not FindingStatus.PROPOSED
        ):
            return VerificationRoute(
                readiness=(
                    VerificationReadiness.NOT_ELIGIBLE
                ),

                finding_type=
                    finding.finding_type,

                raw_finding_type=
                    finding.raw_finding_type,

                reason=(
                    "Only PROPOSED findings may enter "
                    "independent verification."
                ),
            )

        # --------------------------------------------------------------
        # Capability discovery
        # --------------------------------------------------------------

        expected_mode = (
            VerificationMode.STATIC
            if finding.scan_type.value == "STATIC"
            else VerificationMode.RUNTIME
        )

        matches = tuple(
            capability
            for capability
            in self._capabilities.values()
            if (
                finding.finding_type
                in capability.finding_types
                and capability.mode is expected_mode
            )
        )

        # --------------------------------------------------------------
        # No verifier currently registered
        #
        # IMPORTANT:
        # The Finding is NOT discarded.
        # --------------------------------------------------------------

        if not matches:

            label = (
                finding.raw_finding_type
                or finding.finding_type.value
            )

            return VerificationRoute(
                readiness=(
                    VerificationReadiness.UNSUPPORTED
                ),

                finding_type=
                    finding.finding_type,

                raw_finding_type=
                    finding.raw_finding_type,

                reason=(
                    "No independent verification "
                    "capability is currently registered "
                    f"for {label}. "
                    "The proposal is preserved."
                ),
            )

        # --------------------------------------------------------------
        # Avoid silent/ambiguous verifier selection.
        # --------------------------------------------------------------

        if len(matches) > 1:

            ids = ", ".join(
                capability.capability_id
                for capability in matches
            )

            raise ValueError(
                "Finding matches multiple verification "
                "capabilities: "
                f"{ids}. Capability selection must "
                "be unambiguous."
            )

        capability = matches[0]

        # --------------------------------------------------------------
        # Context requirements
        # --------------------------------------------------------------

        missing_fields = tuple(
            field_name
            for field_name
            in capability.required_fields
            if not self._has_context_value(
                getattr(
                    finding,
                    field_name,
                    None,
                )
            )
        )

        if missing_fields:

            return VerificationRoute(
                readiness=(
                    VerificationReadiness.CONTEXT_REQUIRED
                ),

                finding_type=
                    finding.finding_type,

                raw_finding_type=
                    finding.raw_finding_type,

                capability_id=
                    capability.capability_id,

                verifier_id=
                    capability.verifier_id,

                mode=
                    capability.mode,

                missing_fields=
                    missing_fields,

                reason=(
                    "A verification capability exists, "
                    "but additional context is required "
                    "before evidence can be collected."
                ),
            )

        # --------------------------------------------------------------
        # Ready
        # --------------------------------------------------------------

        return VerificationRoute(
            readiness=
                VerificationReadiness.READY,

            finding_type=
                finding.finding_type,

            raw_finding_type=
                finding.raw_finding_type,

            capability_id=
                capability.capability_id,

            verifier_id=
                capability.verifier_id,

            mode=
                capability.mode,

            reason=(
                "Independent verification capability "
                "is ready."
            ),
        )

    def all(
        self,
    ) -> tuple[
        VerificationCapability,
        ...
    ]:

        return tuple(
            self._capabilities.values()
        )

    def __len__(
        self,
    ) -> int:

        return len(
            self._capabilities
        )

    @staticmethod
    def _has_context_value(
        value: object,
    ) -> bool:

        if value is None:
            return False

        if isinstance(
            value,
            str,
        ):
            return bool(
                value.strip()
            )

        return True


def route_finding_for_verification(
    finding: Finding,
    *,
    router: VerificationRouter | None = None,
) -> VerificationRoute:
    """Convenience boundary for service and presentation layers."""

    return (
        router
        or VerificationRouter()
    ).route(
        finding
    )