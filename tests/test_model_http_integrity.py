"""Model transport failures remain bounded fallbacks and keep credentials local."""

from __future__ import annotations

import http.client
import json
import urllib.error

import pytest

import auto_forensics.llama_workflow as model
from auto_forensics.integrity import verify_run
from auto_forensics.pipeline import PipelineConfig, run_case


class Response:
    def __init__(self, payload: bytes, sizes: list[int] | None = None):
        self.payload, self.sizes = payload, sizes

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if self.sizes is not None:
            self.sizes.append(size)
        return self.payload if size < 0 else self.payload[:size]


def _outer(provider: str, content: str) -> bytes:
    return json.dumps({"response": content} if provider == "ollama" else {"choices": [{"message": {"content": content}}]}).encode()


@pytest.fixture(autouse=True)
def no_unstubbed_network(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("A model test attempted unstubbed network access")
    monkeypatch.setattr(model.urllib.request, "urlopen", refuse)


@pytest.mark.parametrize("provider", ["ollama", "openai_compatible"])
@pytest.mark.parametrize("kind", ["outer-list", "invalid-utf8", "deep-outer", "deep-inner", "large-integer", "inner-list", "malformed", "nonfinite"])
def test_malformed_model_responses_return_a_failed_lookup(monkeypatch, provider: str, kind: str):
    deep = "[" * 10_000 + "0" + "]" * 10_000
    cases = {
        "outer-list": b"[]", "invalid-utf8": b"\xff", "deep-outer": ('{"x":' + deep + '}').encode(),
        "deep-inner": _outer(provider, '{"x":' + deep + '}'),
        "large-integer": _outer(provider, '{"n":' + '9' * 5000 + '}'),
        "inner-list": _outer(provider, "[]"), "malformed": b"{bad",
        "nonfinite": _outer(provider, '{"score":NaN}'),
    }
    monkeypatch.setattr(model.urllib.request, "urlopen", lambda *args, **kwargs: Response(cases[kind]))
    workflow = model.LlamaWorkflow("https://model.invalid", "fixture", provider=provider)
    assert workflow._call("synthetic prompt") is None


@pytest.mark.parametrize("provider", ["ollama", "openai_compatible"])
def test_model_response_reads_are_bounded(monkeypatch, provider):
    sizes = []
    payload = _outer(provider, json.dumps({"blob": "x" * (model.MAX_MODEL_RESPONSE_BYTES + 1)}))
    monkeypatch.setattr(model.urllib.request, "urlopen", lambda *args, **kwargs: Response(payload, sizes))
    assert model.LlamaWorkflow("https://model.invalid", "fixture", provider=provider)._call("prompt") is None
    assert sizes == [model.MAX_MODEL_RESPONSE_BYTES + 1]


@pytest.mark.parametrize("provider", ["ollama", "openai_compatible"])
@pytest.mark.parametrize("failure", [TimeoutError, http.client.IncompleteRead, urllib.error.URLError])
def test_model_transport_errors_do_not_escape(monkeypatch, provider, failure):
    def request(*args, **kwargs):
        raise failure(b"synthetic failure")
    monkeypatch.setattr(model.urllib.request, "urlopen", request)
    assert model.LlamaWorkflow("https://model.invalid", "fixture", provider=provider)._call("prompt") is None


def test_model_authorization_is_sent_initially_and_withheld_from_redirects(monkeypatch):
    requests = []
    def request(req, **kwargs):
        assert dict((key.lower(), value) for key, value in req.header_items())["authorization"] == "Bearer stub"
        other = model.urllib.request.HTTPRedirectHandler().redirect_request(req, None, 302, "Found", {}, "https://other.invalid/")
        assert all(key.lower() != "authorization" for key, _ in other.header_items())
        requests.append(req)
        return Response(_outer("openai_compatible", '{"ok":true}'))
    monkeypatch.setattr(model.urllib.request, "urlopen", request)
    workflow = model.LlamaWorkflow("https://model.invalid", "fixture", provider="openai_compatible", api_key="stub")
    assert workflow._call("prompt") == {"ok": True}
    assert len(requests) == 1


@pytest.mark.parametrize("endpoint,expected", [
    ("https://model.invalid", "https://model.invalid/v1/chat/completions"),
    ("https://model.invalid/v1", "https://model.invalid/v1/chat/completions"),
    ("https://model.invalid/v1/", "https://model.invalid/v1/chat/completions"),
    ("https://model.invalid/gateway/v1", "https://model.invalid/gateway/v1/chat/completions"),
])
def test_openai_compatible_base_endpoints_have_one_version_prefix(monkeypatch, endpoint, expected):
    def request(req, **kwargs):
        assert req.full_url == expected
        return Response(_outer("openai_compatible", '{"ok":true}'))
    monkeypatch.setattr(model.urllib.request, "urlopen", request)
    assert model.LlamaWorkflow(endpoint, "fixture", provider="openai_compatible")._call("prompt") == {"ok": True}


def test_malformed_model_summary_does_not_abort_public_pipeline(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sample.bin").write_bytes(b"MZ powershell synthetic evidence")
    def request(req, **kwargs):
        prompt = json.loads(req.data)["prompt"]
        if "Task: case_summary\n" in prompt:
            return Response(b"[]")
        return Response(_outer("ollama", '{"verdict":"supported","findings":[],"timeline_hints":[]}'))
    monkeypatch.setattr(model.urllib.request, "urlopen", request)
    output = tmp_path / "output"
    run_case(PipelineConfig("model-summary", evidence, output, llm_provider="ollama", llama_endpoint="https://model.invalid"))
    assert verify_run(output / "run_manifest.json")["match"] is True
