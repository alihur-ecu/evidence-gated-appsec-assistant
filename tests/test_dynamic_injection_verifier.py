from app.dynamic_analysis.evidence.models import EvidenceBundle, RuntimeObservation, VerificationDecision
from app.dynamic_analysis.verifiers.injection.verifier import InjectionDifferentialVerifier
def o(i,label,length=10,digest="same"):
    return RuntimeObservation(i,label,"GET","https://example.test/",200,length,1.0,digest,{})
def b(*items):
    return EvidenceBundle("e1","INJECTION_DIFFERENTIAL","https://example.test/","GET",tuple(items),parameter="q",baseline_observation_id="base")
def test_identity(): assert InjectionDifferentialVerifier().verifier_id=="injection-differential-verifier"
def test_supports(): assert InjectionDifferentialVerifier().supports(b(o("base","BASELINE"),o("a","TEST_1"),o("b","TEST_2")))
def test_identical_refuted():
    r=InjectionDifferentialVerifier().verify(b(o("base","BASELINE"),o("a","TEST_1"),o("b","TEST_2")))
    assert r.decision==VerificationDecision.REFUTED and r.evidence_id=="e1"
def test_differential_not_overclaimed():
    r=InjectionDifferentialVerifier().verify(b(o("base","BASELINE",10,"base"),o("a","TEST_1",30,"many"),o("b","TEST_2",5,"none")))
    assert r.decision==VerificationDecision.NEEDS_HUMAN and "response_digest" in r.signals_used
def test_one_test_inconclusive():
    r=InjectionDifferentialVerifier().verify(b(o("base","BASELINE"),o("a","TEST_1",20,"different")))
    assert r.decision==VerificationDecision.NEEDS_HUMAN
def test_wrong_capability():
    e=EvidenceBundle("e2","OTHER","https://example.test/","GET",(o("only","BASELINE"),),baseline_observation_id="only")
    try: InjectionDifferentialVerifier().verify(e)
    except TypeError: return
    assert False
