from saboss_scan.scoring import calculate_score
from saboss_scan.utils import normalize_domain


def test_normalize_domain_removes_protocol_and_www():
    assert normalize_domain("https://www.example.com/path") == "example.com"


def test_calculate_score_has_grade_and_percentage():
    fake_results = {
        "ssl": {"https": True, "certificate_valid": True, "days_until_expiry": 120},
        "headers": {"present": [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
        ], "status_code": 200, "final_url": "https://example.com"},
        "dns": {
            "a": ["93.184.216.34"],
            "aaaa": [],
            "mx": ["10 mail.example.com."],
            "txt": ["v=spf1 include:_spf.example.com ~all"],
            "spf": ["v=spf1 include:_spf.example.com ~all"],
            "dmarc": ["v=DMARC1; p=none"],
            "dkim": {},
            "errors": {},
        },
    }
    score = calculate_score(fake_results)
    assert 0 <= score["percentage"] <= 100
    assert score["grade"] in ["A", "B", "C", "D", "E"]
