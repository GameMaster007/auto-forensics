"""Provider responses and old cache data stay bounded, truthful, and JSON-safe."""
from __future__ import annotations

import http.client
import json
import urllib.error

import pytest

import auto_forensics.ioc_enrichment as enrichment
import test_case_scoped_findings as existing
from auto_forensics.db import Database
from auto_forensics.models import IOC, IOCEnrichment

database_backend = existing.database_backend


class Response:
    def __init__(self, payload, read_sizes=None):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.read_sizes = read_sizes
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        if self.read_sizes is not None:
            self.read_sizes.append(size)
        return self.payload if size < 0 else self.payload[:size]


@pytest.fixture(autouse=True)
def forbid_unstubbed_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("Unstubbed network is forbidden")
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", reject)
    monkeypatch.setattr(enrichment.time, "sleep", lambda *args: None)


@pytest.mark.parametrize("payload", [
    {"data": None}, {"data": []},
    {"data": {"attributes": {"last_analysis_stats": []}}},
    {"data": {"attributes": {"last_analysis_stats": {"malicious": "invalid"}}}},
])
def test_malformed_virustotal_result_is_not_a_job_exception(monkeypatch, payload):
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(payload))
    result = enrichment.enrich_ioc(IOC("ioc", "ip", "192.0.2.1"), enrichment.EnrichmentConfig(virustotal_api_key="stub"))
    assert result == []


@pytest.mark.parametrize("payload", [
    {"query_status": "auth_key_required"},
    {"query_status": "temporary_error"},
    {"query_status": "ok", "data": [None]},
])
def test_malwarebazaar_errors_and_invalid_records_do_not_become_verdicts(monkeypatch, payload):
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(payload))
    result = enrichment.enrich_ioc(IOC("ioc", "sha256", "a" * 64), enrichment.EnrichmentConfig(malwarebazaar_api_key="stub"))
    assert result == []


@pytest.mark.parametrize("raw", [b'{"data":{"abuseConfidenceScore":1e309}}', b'{"data":{"abuseConfidenceScore":NaN}}'])
def test_nonfinite_provider_score_does_not_poison_cached_case_projection(database_backend, tmp_path, monkeypatch, raw):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    db = service.db = database_backend
    service.config.abuseipdb_api_key = "stub"
    service.create_case("enrichment-case")
    ioc = IOC("ioc", "ip", "192.0.2.1")
    db.replace_case_iocs("enrichment-case", [ioc])
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(raw))
    service._enrich_iocs_with_cache([ioc])
    json.dumps(service.case_overview("enrichment-case"), allow_nan=False)


def test_live_cache_hit_prevents_repeat_provider_network_calls(tmp_path, monkeypatch):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    service.config.virustotal_api_key = "stub"
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        return Response({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}}}})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    ioc = IOC("ioc", "domain", "synthetic.test")
    first = service._enrich_iocs_with_cache([ioc])
    second = service._enrich_iocs_with_cache([ioc])
    assert first and second
    assert len(calls) == 1


def test_partial_cache_hit_only_fetches_the_missing_provider(tmp_path, monkeypatch):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    service.config.virustotal_api_key = "stub"
    service.config.enable_whois_lookup = True
    calls = {"virustotal": 0, "whois": 0}
    def request(req, **kwargs):
        if "virustotal.com" in req.full_url:
            calls["virustotal"] += 1
            return Response({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}}}})
        calls["whois"] += 1
        raise urllib.error.HTTPError("https://fixture.invalid", 404, "not found", {}, None)
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    ioc = IOC("ioc", "domain", "synthetic.test")
    service._enrich_iocs_with_cache([ioc])
    service._enrich_iocs_with_cache([ioc])
    assert calls == {"virustotal": 1, "whois": 2}


def test_provider_authentication_error_is_not_retained_as_a_negative_cache_hit(tmp_path, monkeypatch):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    service.config.malwarebazaar_api_key = "stub"
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        return Response({"query_status": "auth_key_required"})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    ioc = IOC("ioc", "sha256", "a" * 64)
    service._enrich_iocs_with_cache([ioc])
    cached = service.db.get_cached_ioc_enrichment("sha256", "a" * 64, "malwarebazaar", ttl_minutes=1440)
    assert cached is None


@pytest.mark.parametrize("raw", [b"[" * 10000 + b"0" + b"]" * 10000, b"1" * 5000], ids=["deep-nesting", "oversized-integer"])
def test_malformed_transport_json_is_a_failed_lookup(monkeypatch, raw):
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(raw))
    assert enrichment._request_json("https://fixture.invalid") is None


def test_response_reads_have_a_finite_byte_bound(monkeypatch):
    sizes = []
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response({"padding": "x" * 2_000_000}, sizes))
    enrichment._request_json("https://fixture.invalid")
    assert sizes and all(size > 0 for size in sizes)


def test_truncated_http_body_is_retried(monkeypatch):
    calls = []
    class Truncated(Response):
        def read(self, size=-1):
            raise http.client.IncompleteRead(b"partial", 10)
    def request(*args, **kwargs):
        calls.append(1)
        return Truncated(b"") if len(calls) == 1 else Response({"ok": True})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    assert enrichment._request_json("https://fixture.invalid", retries=1) == {"ok": True}
    assert len(calls) == 2


def test_standard_http_retry_and_terminal_error_controls(monkeypatch):
    calls, sleeps = [], []
    def retryable(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError("https://fixture.invalid", 429, "rate limited", {"Retry-After": "99"}, None)
        return Response({"ok": True})
    monkeypatch.setattr(enrichment.time, "sleep", sleeps.append)
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", retryable)
    assert enrichment._request_json("https://fixture.invalid", retries=1, backoff_max_seconds=8) == {"ok": True}
    assert calls == [1, 1] and sleeps == [8]
    calls.clear()
    def terminal(*args, **kwargs):
        calls.append(1)
        raise urllib.error.HTTPError("https://fixture.invalid", 401, "unauthorized", {}, None)
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", terminal)
    assert enrichment._request_json("https://fixture.invalid", retries=2) is None
    assert calls == [1]


def test_no_configured_provider_makes_no_network_request():
    assert enrichment.enrich_ioc(IOC("ioc", "sha256", "a" * 64), enrichment.EnrichmentConfig()) == []


@pytest.mark.parametrize("header", ["x-apikey", "Auth-Key", "Key"])
def test_provider_api_keys_are_not_forwarded_by_http_redirects(monkeypatch, header):
    redirected = []
    def request(req, **kwargs):
        other = enrichment.urllib.request.HTTPRedirectHandler().redirect_request(
            req, None, 302, "Found", {}, "https://other.invalid/redirected",
        )
        redirected.append(other)
        return Response({"ok": True})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    assert enrichment._request_json("https://fixture.invalid", headers={header: "stub"}) == {"ok": True}
    assert redirected and all(name.lower() != header.lower() for name, _ in redirected[0].header_items())


@pytest.mark.parametrize("status", ["ok", "hash_not_found"])
def test_malwarebazaar_valid_statuses_use_required_auth_header(monkeypatch, status):
    ioc = IOC("ioc", "sha256", "a" * 64)
    payload = {"query_status": status}
    if status == "ok":
        payload["data"] = [{"sha256_hash": ioc.value, "signature": "Synthetic", "tags": ["fixture"]}]
    requests = []
    def request(req, **kwargs):
        requests.append(req)
        return Response(payload)
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    result = enrichment.enrich_ioc(ioc, enrichment.EnrichmentConfig(malwarebazaar_api_key="stub"))
    assert len(requests) == len(result) == 1
    assert dict((key.lower(), value) for key, value in requests[0].header_items())["auth-key"] == "stub"
    assert result[0].verdict == ("malicious" if status == "ok" else "not_found")
    assert result[0].details["query_status"] == status


def test_malwarebazaar_response_for_another_hash_is_not_attached(monkeypatch):
    payload = {"query_status": "ok", "data": [{"sha256_hash": "b" * 64}]}
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(payload))
    assert enrichment.enrich_ioc(IOC("ioc", "sha256", "a" * 64), enrichment.EnrichmentConfig(malwarebazaar_api_key="stub")) == []


@pytest.mark.parametrize("score", [-1, 101, True, "nan", "invalid"])
def test_invalid_abuse_scores_do_not_become_verdicts(monkeypatch, score):
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response({"data": {"abuseConfidenceScore": score}}))
    assert enrichment.enrich_ioc(IOC("ioc", "ip", "192.0.2.1"), enrichment.EnrichmentConfig(abuseipdb_api_key="stub")) == []


def test_abuse_lookup_accepts_equivalent_ipv6_spelling(monkeypatch):
    payload = {"data": {"ipAddress": "2001:0db8:0000:0000:0000:0000:0000:0001", "abuseConfidenceScore": 50}}
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(payload))
    result = enrichment.enrich_ioc(IOC("ioc", "ip", "2001:db8::1"), enrichment.EnrichmentConfig(abuseipdb_api_key="stub"))
    assert result[0].confidence == 0.5 and result[0].verdict == "malicious"


def test_oversized_response_is_rejected_after_a_bounded_read(monkeypatch):
    sizes = []
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *args, **kwargs: Response(b"x" * (enrichment.MAX_ENRICHMENT_BYTES + 2), sizes))
    assert enrichment._request_json("https://fixture.invalid") is None
    assert sizes == [enrichment.MAX_ENRICHMENT_BYTES + 1]


def test_content_length_mismatch_retries_even_when_the_body_is_valid_json(monkeypatch):
    calls = []
    def request(*args, **kwargs):
        response = Response({"ok": True})
        response.headers = {"Content-Length": str(len(response.payload) + (1 if not calls else 0))}
        calls.append(1)
        return response
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    assert enrichment._request_json("https://fixture.invalid", retries=1) == {"ok": True}
    assert len(calls) == 2


@pytest.mark.parametrize("bad_details", ['{"score":NaN}', '{"score":Infinity}', '{bad', '[]', '[' * 10_000 + '0' + ']' * 10_000], ids=["nan", "infinity", "invalid-json", "wrong-shape", "deep-json"])
def test_old_invalid_cache_rows_are_misses_and_cannot_break_case_projection(database_backend, tmp_path, bad_details):
    from test_archive_integrity import _service

    service = _service(tmp_path)
    db = service.db = database_backend
    service.create_case("cache-case")
    ioc = IOC("ioc", "ip", "192.0.2.1")
    db.replace_case_iocs("cache-case", [ioc])
    db.upsert_ioc_enrichment_cache("ip", ioc.value, IOCEnrichment("e1", ioc.ioc_id, "abuseipdb", "unknown", 0.5, details={"abuse_confidence_score": 0}))
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute("UPDATE ioc_enrichment_cache SET details_json=?", (bad_details,))
    else:
        with db.engine.begin() as con:
            con.execute(db.ioc_enrichment_cache.update().values(details_json=bad_details))
    assert db.get_cached_ioc_enrichment("ip", ioc.value, "abuseipdb", ttl_minutes=60) is None
    assert db.get_case_ioc_enrichments("cache-case") == []
    json.dumps(service.case_overview("cache-case"), allow_nan=False)


def test_old_ambiguous_malwarebazaar_negative_cache_is_not_reused(database_backend, tmp_path):
    db = database_backend
    existing._cases(db, tmp_path)
    ioc = IOC("ioc", "sha256", "a" * 64)
    db.replace_case_iocs("case-one", [ioc])
    record = IOCEnrichment("e1", ioc.ioc_id, "malwarebazaar", "not_found", 0.6, details={"query_status": "hash_not_found"})
    db.upsert_ioc_enrichment_cache(ioc.ioc_type, ioc.value, record)
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute("UPDATE ioc_enrichment_cache SET details_json='{}'")
    else:
        with db.engine.begin() as con:
            con.execute(db.ioc_enrichment_cache.update().values(details_json="{}"))
    assert db.get_cached_ioc_enrichment(ioc.ioc_type, ioc.value, "malwarebazaar", ttl_minutes=60) is None
    assert db.get_case_ioc_enrichments("case-one") == []


@pytest.mark.parametrize("score,details", [(float("nan"), {}), (float("inf"), {}), (-1, {}), (True, {}), (0.5, {"score": float("nan")})])
def test_invalid_cache_writes_are_rejected_before_persistence(database_backend, score, details):
    db = database_backend
    record = IOCEnrichment("e1", "ioc", "fixture", "unknown", score, details=details)
    with pytest.raises(ValueError, match="finite valid data"):
        db.upsert_ioc_enrichment_cache("ip", "192.0.2.1", record)
    assert db.get_cached_ioc_enrichment("ip", "192.0.2.1", "fixture", ttl_minutes=0) is None


def test_cache_preserves_fetch_time_and_expiry_on_every_backend(database_backend):
    db = database_backend
    fetched = "2001-01-01T00:00:00Z"
    record = IOCEnrichment("e1", "ioc", "fixture", "unknown", 0.5, fetched_at=fetched)
    db.upsert_ioc_enrichment_cache("ip", "192.0.2.1", record)
    assert db.get_cached_ioc_enrichment("ip", "192.0.2.1", "fixture", ttl_minutes=60) is None
    assert db.get_cached_ioc_enrichment("ip", "192.0.2.1", "fixture", ttl_minutes=0).fetched_at == fetched


@pytest.mark.parametrize("kind,field,length", [("md5", "md5_hash", 32), ("sha1", "sha1_hash", 40), ("sha256", "sha256_hash", 64)])
def test_known_valid_malwarebazaar_hash_algorithms_are_preserved(monkeypatch, kind, field, length):
    ioc = IOC("ioc", kind, "A" * length)
    requests = []
    def request(req, **kwargs):
        requests.append(req)
        return Response({"query_status": "ok", "data": [{field: "a" * length, "signature": "Fixture", "tags": ["synthetic"]}]})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    result = enrichment.enrich_ioc(ioc, enrichment.EnrichmentConfig(malwarebazaar_api_key="stub"))
    assert len(requests) == len(result) == 1
    assert result[0].verdict == "malicious" and result[0].confidence == .9


@pytest.mark.parametrize("score,verdict,confidence", [(0, "unknown", .3), (29, "suspicious", .3), (50, "malicious", .5), (100, "malicious", 1.)])
def test_valid_abuse_scores_and_identity_survive(monkeypatch, score, verdict, confidence):
    def request(*args, **kwargs):
        return Response({"data": {"ipAddress": "192.0.2.1", "abuseConfidenceScore": score, "usageType": "Fixture"}})
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    result = enrichment.enrich_ioc(IOC("ioc", "ip", "192.0.2.1"), enrichment.EnrichmentConfig(abuseipdb_api_key="stub"))
    assert len(result) == 1 and (result[0].verdict, result[0].confidence) == (verdict, confidence)


def test_valid_multi_provider_result_is_cached_without_extra_requests(database_backend, tmp_path, monkeypatch):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    service.db = database_backend
    service.config.virustotal_api_key = service.config.abuseipdb_api_key = "stub"
    service.config.enable_whois_lookup = True
    calls = []
    def request(req, **kwargs):
        calls.append(req.full_url)
        if "virustotal.com" in req.full_url:
            return Response({"data": {"id": "192.0.2.1", "attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 6}}}})
        if "abuseipdb.com" in req.full_url:
            return Response({"data": {"ipAddress": "192.0.2.1", "abuseConfidenceScore": 50}})
        if "rdap.org" in req.full_url:
            return Response({"handle": "Fixture", "status": ["active"]})
        raise AssertionError("Unexpected provider")
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", request)
    ioc = IOC("ioc", "ip", "192.0.2.1")
    first = service._enrich_iocs_with_cache([ioc])
    second = service._enrich_iocs_with_cache([ioc])
    assert len(first) == len(second) == len(calls) == 3
    assert {(row.provider, row.verdict) for row in second} == {("virustotal", "malicious"), ("abuseipdb", "malicious"), ("whois", "informational")}


@pytest.mark.parametrize("provider,bad_details", [
    ("abuseipdb", {"abuse_confidence_score": 101, "usage_type": None}),
    ("virustotal", {"analysis_stats": {"malicious": -1, "suspicious": 2, "harmless": 0}}),
])
def test_legacy_cache_with_provider_invalid_scores_is_not_a_trusted_verdict(database_backend, tmp_path, provider, bad_details):
    db = database_backend
    existing._cases(db, tmp_path)
    ioc = IOC("ioc", "ip", "192.0.2.1")
    db.replace_case_iocs("case-one", [ioc])
    good = {"abuse_confidence_score": 100, "usage_type": None} if provider == "abuseipdb" else {"analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 0}}
    db.upsert_ioc_enrichment_cache("ip", ioc.value, IOCEnrichment("e", ioc.ioc_id, provider, "malicious", 1., good))
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute("UPDATE ioc_enrichment_cache SET details_json=?", (json.dumps(bad_details),))
    else:
        with db.engine.begin() as con:
            con.execute(db.ioc_enrichment_cache.update().values(details_json=json.dumps(bad_details)))
    # Both corrupt shapes were accepted by the pre-fix provider adapters and
    # produced malicious confidence1, so these can exist without manual tampering.
    observed = (db.get_cached_ioc_enrichment("ip", ioc.value, provider, ttl_minutes=60), db.get_case_ioc_enrichments("case-one"))
    assert observed == (None, [])
