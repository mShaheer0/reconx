import json

from recon.passive import _normalize_probe_targets, _chunked, run_dnsx


def test_normalize_probe_targets_adds_schemes():
    targets = ["example.com", "http://already.com", "https://secure.com"]
    result = _normalize_probe_targets(targets)
    assert "https://example.com" in result
    assert "http://example.com" in result
    assert "http://already.com" in result
    assert "https://secure.com" in result


def test_normalize_probe_targets_dedupes():
    targets = ["example.com", "example.com"]
    result = _normalize_probe_targets(targets)
    assert result.count("https://example.com") == 1
    assert result.count("http://example.com") == 1


def test_normalize_probe_targets_skips_empty():
    assert _normalize_probe_targets(["", None]) == []


def test_chunked_batches():
    items = list(range(10))
    batches = _chunked(items, 3)
    assert len(batches) == 4
    assert batches[0] == [0, 1, 2]
    assert batches[-1] == [9]


def test_chunked_empty():
    assert _chunked([], 5) == []


def test_run_dnsx_empty_domains():
    assert run_dnsx([], "/tmp", 10) == []


def test_run_dnsx_missing_binary(monkeypatch):
    import recon.passive as passive

    def fake_resolve(name, env_var=None):
        raise RuntimeError(f"not found: {name}")

    monkeypatch.setattr(passive, "resolve_projectdiscovery_binary", fake_resolve)
    assert run_dnsx(["example.com"], "/tmp", 10) == []


def test_run_dnsx_parses_json_output(monkeypatch, tmp_path):
    import recon.passive as passive

    sample = json.dumps({
        "host": "example.com",
        "a": ["1.2.3.4"],
        "aaaa": ["::1"],
        "mx": ["mail.example.com"],
    }) + "\n"
    sample += json.dumps({
        "host": "example.com",
        "ns": ["ns1.example.com", "ns2.example.com"],
    }) + "\n"

    class FakeProc:
        stdout = sample.encode()
        stderr = b""
        returncode = 0

    def fake_run(cmd, **kwargs):
        assert "dnsx" in cmd[0]
        return FakeProc()

    monkeypatch.setattr(passive.subprocess, "run", fake_run)
    monkeypatch.setattr(passive, "resolve_projectdiscovery_binary", lambda name, env_var=None: "/fake/dnsx")

    results = passive.run_dnsx(["example.com"], str(tmp_path), 10)
    assert len(results) == 5
    assert results[0]["record_type"] == "A"
    assert results[0]["record_value"] == "1.2.3.4"
    assert results[1]["record_type"] == "AAAA"
    assert results[1]["record_value"] == "::1"
    assert results[2]["record_type"] == "MX"
    assert results[2]["record_value"] == "mail.example.com"
    assert results[3]["record_type"] == "NS"
    assert results[3]["record_value"] == "ns1.example.com"
    assert results[4]["record_type"] == "NS"
    assert results[4]["record_value"] == "ns2.example.com"
