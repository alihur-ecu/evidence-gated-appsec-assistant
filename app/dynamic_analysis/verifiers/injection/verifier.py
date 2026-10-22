from app.dynamic_analysis.evidence.models import (
    EvidenceBundle,
    VerificationDecision,
    VerificationResult,
)
from app.dynamic_analysis.verifiers.base import (
    EvidenceVerifier,
)


class InjectionDifferentialVerifier(EvidenceVerifier):
    verifier_id = "injection-differential-verifier"
    capability = "INJECTION_DIFFERENTIAL"

    def supports(
        self,
        evidence: EvidenceBundle,
    ) -> bool:
        return (
            isinstance(
                evidence,
                EvidenceBundle,
            )
            and evidence.capability
            == self.capability
        )

    def verify(
        self,
        evidence: EvidenceBundle,
    ) -> VerificationResult:
        if not self.supports(evidence):
            raise TypeError(
                "evidence must be an "
                "INJECTION_DIFFERENTIAL "
                "EvidenceBundle."
            )

        baseline = next(
            (
                observation
                for observation
                in evidence.observations
                if observation.observation_id
                == evidence.baseline_observation_id
            ),
            None,
        )

        tests = tuple(
            observation
            for observation
            in evidence.observations
            if observation.observation_id
            != evidence.baseline_observation_id
        )

        if baseline is None or len(tests) < 2:
            return VerificationResult(
                evidence_id=evidence.evidence_id,
                verifier_id=self.verifier_id,
                decision=(
                    VerificationDecision.NEEDS_HUMAN
                ),
                reasons=(
                    "Differential verification "
                    "requires one baseline and at "
                    "least two test observations.",
                ),
                signals_used=(
                    "baseline_present",
                    "test_observation_count",
                ),
            )

        def different(a, b):
            return (
                a.status_code
                != b.status_code
                or a.response_length
                != b.response_length
                or a.response_digest
                != b.response_digest
            )

        from_baseline = any(
            different(
                observation,
                baseline,
            )
            for observation in tests
        )

        tests_differ = any(
            different(
                tests[first],
                tests[second],
            )
            for first in range(len(tests))
            for second in range(
                first + 1,
                len(tests),
            )
        )

        baseline_error = bool(
            baseline.metadata.get(
                "error_detected",
                False,
            )
        )

        test_errors = tuple(
            observation
            for observation in tests
            if observation.metadata.get(
                "error_detected",
                False,
            )
        )

        new_error_in_test = (
            not baseline_error
            and bool(test_errors)
        )

        error_families = {
            observation.metadata.get(
                "error_family"
            )
            for observation in test_errors
            if observation.metadata.get(
                "error_family"
            )
        }

        generic_signals = (
            "response_length",
            "status_code",
            "response_digest",
        )

        error_signals = (
            "error_detected",
            "error_family",
            "error_signature",
        )

        if (
            new_error_in_test
            and len(test_errors) >= 2
            and from_baseline
        ):
            return VerificationResult(
                evidence_id=evidence.evidence_id,
                verifier_id=self.verifier_id,
                decision=(
                    VerificationDecision.PROVED
                ),
                reasons=(
                    "The functional baseline did "
                    "not contain a database/parser "
                    "error, while multiple bounded "
                    "test observations produced "
                    "deterministic error signals.",
                ),
                signals_used=(
                    generic_signals
                    + error_signals
                ),
            )

        if new_error_in_test:
            family_text = (
                ", ".join(
                    sorted(error_families)
                )
                if error_families
                else "unknown"
            )

            return VerificationResult(
                evidence_id=evidence.evidence_id,
                verifier_id=self.verifier_id,
                decision=(
                    VerificationDecision.NEEDS_HUMAN
                ),
                reasons=(
                    "A new database/parser error "
                    "signal appeared during bounded "
                    "testing, but the evidence was "
                    "not sufficiently reproducible "
                    "for deterministic proof. "
                    f"Observed family: {family_text}.",
                ),
                signals_used=(
                    generic_signals
                    + error_signals
                ),
            )

        if from_baseline and tests_differ:
            return VerificationResult(
                evidence_id=evidence.evidence_id,
                verifier_id=self.verifier_id,
                decision=(
                    VerificationDecision.NEEDS_HUMAN
                ),
                reasons=(
                    "Meaningful differential "
                    "response behaviour was "
                    "observed, but generic response "
                    "differences alone do not prove "
                    "an injection vulnerability.",
                ),
                signals_used=generic_signals,
            )

        return VerificationResult(
            evidence_id=evidence.evidence_id,
            verifier_id=self.verifier_id,
            decision=(
                VerificationDecision.REFUTED
            ),
            reasons=(
                "The bounded differential "
                "observations did not produce "
                "meaningful response differences "
                "or new deterministic error "
                "signals.",
            ),
            signals_used=(
                generic_signals
                + error_signals
            ),
        )