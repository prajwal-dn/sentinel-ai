import httpx
import pytest

from app.config import Settings
from app.intel import enrich
from app.llm import LLMAuthError, LLMError, LLMTimeout, build_provider, llm_status


def S(**kw):
    base = dict(db_path=":memory:", llm_provider="anthropic", llm_model="m", llm_api_key="k", llm_base_url=None, llm_timeout=5)
    base.update(kw)
    return Settings(**base)


def test_status_variants():
    assert llm_status(S(llm_provider="none"))["status"] == "NOT_CONFIGURED"
    assert llm_status(S(llm_model=None))["status"] == "MISCONFIGURED"
    assert llm_status(S(llm_provider="bogus"))["status"] == "MISCONFIGURED"
    assert llm_status(S())["status"] == "CONFIGURED"
    assert build_provider(S(llm_provider="none")) is None


def test_anthropic_success_and_request_shape():
    seen = {}
    def h(r):
        seen["h"], seen["b"] = dict(r.headers), r.read()
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hi"}]})
    p = build_provider(S(), httpx.MockTransport(h))
    assert p.complete("sys", [{"role": "user", "content": "x"}]) == "hi"
    assert seen["h"]["x-api-key"] == "k" and b'"model":"m"' in seen["b"].replace(b" ", b"")


@pytest.mark.parametrize("resp,exc", [(httpx.Response(401), LLMAuthError), (httpx.Response(429), LLMError), (httpx.Response(500), LLMError),
                                      (httpx.Response(200, json={"nope": 1}), LLMError), (httpx.Response(200, text="<html>"), LLMError)])
def test_provider_failures(resp, exc):
    p = build_provider(S(), httpx.MockTransport(lambda r: resp))
    with pytest.raises(exc):
        p.complete("s", [])


def test_timeout_maps_to_llmtimeout():
    def h(r):
        raise httpx.ReadTimeout("slow")
    with pytest.raises(LLMTimeout):
        build_provider(S(), httpx.MockTransport(h)).complete("s", [])


def test_openai_compat_and_base_url_validation():
    p = build_provider(S(llm_provider="openai", llm_base_url="http://localhost:11434/v1"),
                       httpx.MockTransport(lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})))
    assert p.complete("s", []) == "ok"
    with pytest.raises(LLMError):
        build_provider(S(llm_provider="openai", llm_base_url="http://evil.example/v1"))


def test_error_messages_never_leak_key():
    p = build_provider(S(llm_api_key="SUPERSECRETKEY"), httpx.MockTransport(lambda r: httpx.Response(401)))
    with pytest.raises(LLMAuthError) as e:
        p.complete("s", [])
    assert "SUPERSECRETKEY" not in str(e.value)


# ---------------- threat intel
def inv_with(ips):
    return {"iocs": [{"type": "ip", "value": v, "scope": sc, "enrichment": {"status": "PROVIDER_NOT_CONFIGURED"}} for v, sc in ips]}


def test_enrichment_statuses():
    inv = inv_with([("45.33.32.156", "external"), ("10.0.0.1", "internal")])
    enrich(inv, Settings(db_path=":memory:", abuseipdb_key=None))
    assert inv["iocs"][0]["enrichment"]["status"] == "PROVIDER_NOT_CONFIGURED"

    ok = httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 12, "countryCode": "XX", "isp": "i"}}))
    inv = inv_with([("45.33.32.156", "external"), ("10.0.0.1", "internal")])
    enrich(inv, Settings(db_path=":memory:", abuseipdb_key="k"), ok)
    assert inv["iocs"][0]["enrichment"]["status"] == "MATCH" and inv["iocs"][1]["enrichment"]["status"] == "NOT_APPLICABLE"

    for resp, want in [(httpx.Response(200, json={"data": {"totalReports": 0}}), "NO_MATCH"), (httpx.Response(503), "PROVIDER_UNAVAILABLE"),
                       (httpx.Response(401), "LOOKUP_FAILED"), (httpx.Response(200, json={}), "LOOKUP_FAILED")]:
        inv = inv_with([("45.33.32.156", "external")])
        enrich(inv, Settings(db_path=":memory:", abuseipdb_key="k"), httpx.MockTransport(lambda r, resp=resp: resp))
        assert inv["iocs"][0]["enrichment"]["status"] == want


def test_enrichment_timeout_marks_unavailable():
    def h(r):
        raise httpx.ConnectTimeout("t")
    inv = inv_with([("45.33.32.156", "external")])
    enrich(inv, Settings(db_path=":memory:", abuseipdb_key="k"), httpx.MockTransport(h))
    assert inv["iocs"][0]["enrichment"]["status"] == "PROVIDER_UNAVAILABLE"
