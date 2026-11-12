"""Unit tests for the domain/rule matching engine."""
from datetime import datetime, timezone

from netguard.services.rules import (
    domain_matches,
    in_schedule,
    normalize_domain,
    remaining_curfew_time,
)


def test_normalize_domain():
    assert normalize_domain("HTTPS://Example.COM/path?x=1") == "example.com"
    assert normalize_domain(" example.com. ") == "example.com"


def test_exact_and_subdomain_match():
    assert domain_matches("example.com", "example.com")
    assert domain_matches("ads.example.com", "example.com")
    assert not domain_matches("notexample.com", "example.com")


def test_wildcard_subdomain_only():
    assert domain_matches("a.example.com", "*.example.com")
    assert not domain_matches("example.com", "*.example.com")


def test_substring_pattern():
    assert domain_matches("cdn.pornhub.com", "*pornhub*")
    assert not domain_matches("example.org", "*pornhub*")


def test_schedule_same_day_window():
    monday_noon = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)  # Monday
    assert in_schedule(monday_noon, "0", "09:00", "17:00")
    assert not in_schedule(monday_noon, "1", "09:00", "17:00")


def test_schedule_crossing_midnight():
    monday_23 = datetime(2026, 11, 9, 23, 0, tzinfo=timezone.utc)
    tuesday_02 = datetime(2026, 11, 10, 2, 0, tzinfo=timezone.utc)
    # a 21:00-07:00 window listed for Monday covers Monday night into Tuesday
    assert in_schedule(monday_23, "0", "21:00", "07:00")
    assert in_schedule(tuesday_02, "0", "21:00", "07:00")
    # Wednesday 02:00 is not covered when only Monday is listed
    wednesday_02 = datetime(2026, 11, 11, 2, 0, tzinfo=timezone.utc)
    assert not in_schedule(wednesday_02, "0", "21:00", "07:00")
    assert in_schedule(wednesday_02, "0,1,2,3,4", "21:00", "07:00")


def test_remaining_curfew_time():
    now = datetime(2026, 11, 9, 23, 0, tzinfo=timezone.utc)
    remaining = remaining_curfew_time(now, "21:00", "07:00")
    assert remaining.total_seconds() == 8 * 3600
