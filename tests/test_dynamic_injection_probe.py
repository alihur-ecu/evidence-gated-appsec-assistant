import requests
from app.dynamic_analysis.probes.injection.probe import InjectionDifferentialProbe, InjectionProbeInput
class R:
    def __init__(self,url,text):
        self.url=url; self.text=text; self.status_code=200; self.content=text.encode(); self.headers={"Content-Type":"text/html"}; self.history=[]
class S(requests.Session):
    def __init__(self): super().__init__(); self.calls=[]
    def get(self,url,**kw): self.calls.append(("GET",url,kw)); return R(url,str(kw["params"]["q"]))
    def post(self,url,**kw): self.calls.append(("POST",url,kw)); return R(url,str(kw["data"]["q"]))
def inp(method="GET"): return InjectionProbeInput("https://example.test/search",method,"q","normal",("a","b"),{"mode":"search"})
def test_identity(): assert InjectionDifferentialProbe().probe_id=="injection-differential-probe"
def test_supports(): assert InjectionDifferentialProbe().supports(inp())
def test_get():
    s=S(); e=InjectionDifferentialProbe().collect(context=inp(),session=s)
    assert len(e.observations)==3 and e.parameter=="q" and len(s.calls)==3
def test_post():
    s=S(); e=InjectionDifferentialProbe().collect(context=inp("POST"),session=s)
    assert e.method=="POST" and all(c[0]=="POST" for c in s.calls)
def test_fixed():
    s=S(); InjectionDifferentialProbe().collect(context=inp(),session=s)
    assert s.calls[0][2]["params"]["mode"]=="search"
def test_observation_contract():
    s=S(); o=InjectionDifferentialProbe().collect(context=inp(),session=s).observations[0]
    assert o.method=="GET" and o.url and o.status_code==200 and o.response_digest
def test_bad_method():
    try: inp("DELETE")
    except ValueError: return
    assert False
