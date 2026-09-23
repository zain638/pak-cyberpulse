"""UI/API compatibility guards for the pinned dependency versions.

Regression test for the v4 bug where new panels used
st.dataframe(..., width="stretch") — an API that does not exist in the
pinned streamlit==1.40.1 (it raises TypeError at render time, crashing the
tab in the shipped binary). The 1.40.1-compatible spelling is
use_container_width=True.
"""
from pathlib import Path

PROJ = Path(__file__).resolve().parent.parent


def _py_files():
    files = [PROJ / "app.py"]
    files += sorted((PROJ / "modules").glob("*.py"))
    files += sorted((PROJ / "database").glob("*.py"))
    return files


def test_no_unsupported_st_width_kwarg():
    """No st.* call may use width='stretch' (unsupported in streamlit 1.40.1)."""
    offenders = []
    for path in _py_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if 'width="stretch"' in line or "width='stretch'" in line:
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, (
        "unsupported width='stretch' for pinned streamlit 1.40.1: "
        + ", ".join(offenders)
    )


def test_no_use_container_width_false_positive():
    """Sanity: the suite actually scans the new v4 panels."""
    scanned = {p.name for p in _py_files()}
    assert {"anomaly_engine.py", "connectors.py", "threat_intel.py"} <= scanned
