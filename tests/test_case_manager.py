"""Lifecycle, transition-guard, SLA and timeline tests for case_manager."""

from datetime import datetime, timedelta, timezone

import pytest

from modules.case_manager import SLA_HOURS, STATUSES, CaseManager

PATH = ["open", "triage", "contained", "eradicated", "recovered", "closed"]


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _retime(case_mgr, case_id, created_ago_h, due_in_h):
    """Directly rewrite a case's timestamps (tests SLA math, not wall clock)."""
    now = datetime.now(timezone.utc)
    created = _fmt(now - timedelta(hours=created_ago_h))
    due = _fmt(now + timedelta(hours=due_in_h))
    with case_mgr.db.lock, case_mgr.db.connect() as conn:
        conn.execute(
            "UPDATE cases SET created_at = ?, sla_due = ? WHERE case_id = ?",
            (created, due, case_id),
        )
        conn.commit()


def test_full_lifecycle_open_to_closed(case_mgr):
    cid = case_mgr.create_case("Brute-force on NADRA-IDC", "demo", "High", "analyst")
    for nxt in PATH[1:]:
        case_mgr.transition(cid, nxt, "analyst")
    assert case_mgr.get_case(cid)["status"] == "closed"
    assert case_mgr.list_cases(status="closed")


def test_invalid_jump_raises_value_error(case_mgr):
    cid = case_mgr.create_case("Jump test", "demo", "Medium")
    with pytest.raises(ValueError):
        case_mgr.transition(cid, "contained", "analyst")  # open -> contained is illegal
    with pytest.raises(ValueError):
        case_mgr.transition(cid, "nope", "analyst")       # unknown status
    assert case_mgr.get_case(cid)["status"] == "open"      # state untouched


def test_closed_case_can_reopen_to_triage(case_mgr):
    cid = case_mgr.create_case("Reopen test", "demo", "Low")
    for nxt in PATH[1:]:
        case_mgr.transition(cid, nxt, "analyst")
    case_mgr.transition(cid, "triage", "analyst")
    assert case_mgr.get_case(cid)["status"] == "triage"
    with pytest.raises(ValueError):
        case_mgr.transition(cid, "closed", "analyst")  # triage -> closed illegal


def test_sla_status_ok_warning_breached_closed(case_mgr):
    cid = case_mgr.create_case("SLA math", "demo", "Critical")  # 4h SLA
    assert case_mgr.sla_status(case_mgr.get_case(cid)) == "ok"
    assert case_mgr.sla_remaining(case_mgr.get_case(cid)).startswith(("3h", "4h"))

    _retime(case_mgr, cid, created_ago_h=3.5, due_in_h=0.5)  # 12.5% of window left
    assert case_mgr.sla_status(case_mgr.get_case(cid)) == "warning"

    _retime(case_mgr, cid, created_ago_h=6, due_in_h=-2)      # deadline passed
    assert case_mgr.sla_status(case_mgr.get_case(cid)) == "breached"

    for nxt in PATH[1:]:
        case_mgr.transition(cid, nxt, "analyst")
    assert case_mgr.sla_status(case_mgr.get_case(cid)) == "closed"


def test_add_note_and_case_timeline_ordering(case_mgr):
    cid = case_mgr.create_case("Timeline test", "demo", "High")
    case_mgr.transition(cid, "triage", "analyst")
    case_mgr.add_note(cid, "analyst", "first analyst note")
    case_mgr.add_note(cid, "senior", "second analyst note")

    timeline = case_mgr.case_timeline(cid)
    assert timeline[0]["kind"] == "created"
    summaries = [e["summary"] for e in timeline]
    assert any("Case opened" in s for s in summaries)
    assert any("open -> triage" in s for s in summaries)
    assert timeline[-2]["summary"] == "first analyst note"
    assert timeline[-1]["summary"] == "second analyst note"
    assert timeline[-1]["author"] == "senior"
    kinds = [e["kind"] for e in timeline]
    assert kinds.count("status_change") >= 1 and kinds.count("note") == 2


def test_create_case_validation(case_mgr):
    with pytest.raises(ValueError):
        case_mgr.create_case("   ", "demo", "High")
    with pytest.raises(ValueError):
        case_mgr.create_case("Bad severity", "demo", "Urgent")
    with pytest.raises(ValueError):
        case_mgr.transition(999999, "triage", "analyst")
    with pytest.raises(ValueError):
        case_mgr.add_note(case_mgr.create_case("n", "d", "Low"), "a", "   ")


def test_sla_hours_drive_due_dates(case_mgr):
    for sev, hours in SLA_HOURS.items():
        cid = case_mgr.create_case(f"SLA {sev}", "demo", sev)
        case = case_mgr.get_case(cid)
        created = datetime.strptime(case["created_at"], "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc
        )
        due = datetime.strptime(case["sla_due"], "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc
        )
        assert (due - created).total_seconds() == pytest.approx(hours * 3600, abs=2)
    assert set(STATUSES) == set(PATH)
