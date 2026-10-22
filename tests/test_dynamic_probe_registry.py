import pytest

from app.dynamic_analysis.evidence import (
    EvidenceBundle,
    RuntimeObservation,
)
from app.dynamic_analysis.probes import DynamicProbe, ProbeRegistry


class FakeProbe(DynamicProbe):
    probe_id = "fake-probe"
    capability = "fake-capability"

    def supports(self, context):
        return context.get("enabled", False)

    def collect(self, *, context, session):
        observation = RuntimeObservation(
            observation_id="obs-1",
            label="test",
            method="GET",
            url=context["url"],
            status_code=200,
            response_length=10,
        )
        return EvidenceBundle(
            evidence_id="evidence-1",
            capability=self.capability,
            endpoint=context["url"],
            method="GET",
            observations=(observation,),
        )


class SecondProbe(FakeProbe):
    probe_id = "second-probe"


def test_registry_registers_and_returns_probe():
    probe = FakeProbe()
    registry = ProbeRegistry([probe])

    assert len(registry) == 1
    assert registry.get("fake-probe") is probe


def test_registry_selects_only_applicable_probes():
    registry = ProbeRegistry([FakeProbe(), SecondProbe()])

    assert len(registry.applicable({"enabled": True})) == 2
    assert registry.applicable({"enabled": False}) == ()


def test_registry_rejects_duplicate_probe_ids():
    registry = ProbeRegistry([FakeProbe()])

    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeProbe())


def test_probe_collects_evidence_without_verifying_it():
    probe = FakeProbe()
    evidence = probe.collect(
        context={
            "enabled": True,
            "url": "https://example.test/",
        },
        session=object(),
    )

    assert evidence.capability == "fake-capability"
    assert not hasattr(evidence, "decision")
