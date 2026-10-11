from saboss_scan.findings import Finding
from saboss_scan.scoring import calculate_score


def make(status, severity="medium", category="tls"):
    return Finding(id=f"x.{status}", category=category, title="t", severity=severity, status=status)


def test_all_passing_checks_give_full_score():
    score = calculate_score([make("pass", "high"), make("pass", "medium"), make("pass", "low")])
    assert score["percentage"] == 100
    assert score["grade"] == "A"
    assert score["complete"] is True


def test_warning_earns_half_and_fail_earns_nothing():
    score = calculate_score([make("warning", "medium"), make("fail", "medium")])
    # (2.5 + 0) / 10
    assert score["earned"] == 2.5
    assert score["possible"] == 10
    assert score["percentage"] == 25


def test_not_checked_is_excluded_from_score():
    score = calculate_score([make("pass", "medium"), make("not_checked", "high")])
    assert score["percentage"] == 100
    assert score["checks_completed"] == 1
    assert score["checks_total"] == 2
    assert score["complete"] is False


def test_info_findings_are_not_scored():
    score = calculate_score([make("pass", "medium"), make("fail", "info")])
    assert score["percentage"] == 100


def test_failed_high_severity_check_caps_grade_at_d():
    findings = [make("pass", "medium") for _ in range(10)] + [make("fail", "high")]
    score = calculate_score(findings)
    assert score["percentage"] == 83  # 50 / 60, would normally be a B
    assert score["grade"] == "D"
    assert score["high_risk_failed"] is True


def test_no_completed_checks_gives_no_score():
    score = calculate_score([make("not_checked"), make("not_checked")])
    assert score["percentage"] is None
    assert score["grade"] == "N/A"


def test_category_breakdown():
    score = calculate_score([make("pass", "high", "tls"), make("fail", "low", "email")])
    assert score["categories"]["tls"] == {"earned": 10, "possible": 10}
    assert score["categories"]["email"] == {"earned": 0, "possible": 2}
