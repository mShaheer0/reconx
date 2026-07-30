import re
from recon.aggregator import clean_and_mask, _mask_text


def test_mask_text_redacts_ips():
    assert "10.0.0.1" not in _mask_text("server at 10.0.0.1")
    assert "<REDACTED_IP>" in _mask_text("server at 10.0.0.1")


def test_mask_text_redacts_tokens():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwx yz012345"
    masked = _mask_text(text)
    assert "abcdefghijklmnopqrstuvwx" not in masked
    assert "Bearer" not in masked


def test_mask_text_redacts_long_base64():
    text = "header " + "A" * 50
    masked = _mask_text(text)
    assert "A" * 50 not in masked
    assert "<REDACTED_TOKEN>" in masked


def test_clean_and_mask_dedupes_httpx():
    subdomains = ["a.example.com", "b.example.com"]
    httpx = [
        {"url": "https://a.example.com", "status_code": 200, "title": "A", "tech": "nginx"},
        {"url": "https://a.example.com", "status_code": 200, "title": "A", "tech": "nginx"},
    ]
    result = clean_and_mask("example.com", subdomains, httpx, [], [], 300, False)
    assert result["live_hosts"] == 1
    assert result["subdomains_found"] == 2


def test_clean_and_mask_normalizes_tech():
    httpx = [
        {"url": "https://a.example.com", "status_code": 200, "title": "A", "tech": "nginx, cloudflare"},
    ]
    result = clean_and_mask("example.com", ["a.example.com"], httpx, [], [], 300, False)
    assert "nginx" in result["technologies"]
    assert "cloudflare" in result["technologies"]


def test_clean_and_mask_counts_severities():
    nuclei = [
        {"severity": "high", "name": "XSS", "matched_at": "https://a.example.com", "description": "xss"},
        {"severity": "high", "name": "SQLi", "matched_at": "https://b.example.com", "description": "sqli"},
        {"severity": "low", "name": "Info", "matched_at": "https://c.example.com", "description": "info"},
    ]
    result = clean_and_mask("example.com", [], [], nuclei, [], 300, True)
    assert result["severity_counts"]["high"] == 2
    assert result["severity_counts"]["low"] == 1


def test_clean_and_mask_truncates_description():
    long_desc = "A" * 500
    nuclei = [{"severity": "info", "name": "Test", "matched_at": "http://x", "description": long_desc}]
    result = clean_and_mask("example.com", [], [], nuclei, [], 100, True)
    assert len(result["findings"][0]["description"]) <= 103  # 100 + "..."


def test_clean_and_mask_includes_dns():
    dns = [
        {"host": "example.com", "record_type": "A", "record_value": "1.2.3.4"},
        {"host": "example.com", "record_type": "MX", "record_value": "mail.example.com"},
        {"host": "example.com", "record_type": "A", "record_value": "1.2.3.4"},
    ]
    result = clean_and_mask("example.com", ["example.com"], [], [], dns, 300, False)
    assert result["dns_record_types"]["A"] == 2
    assert result["dns_record_types"]["MX"] == 1
    assert len(result["dns_records"]) == 3
