import pytest

from adaudit.engine import CATEGORIES, Finding
from adaudit.plan import build_plan
from adaudit.scoring import SEVERITY_POINTS, level, score
from conftest import fired


def mk(sev, cat, effort="quick", fid="AD-TST-001"):
    return Finding(id=fid, title="t", severity=sev, category=cat, effort=effort, why="w",
                   remediation="r", references=[], mitre=[], evidence=["e"], affected=1)


def test_empty_is_zero():
    s = score([])
    assert s["global"] == 0 and s["level"] == "faible"
    assert set(s["categories"]) == set(CATEGORIES)


def test_points_per_severity():
    assert SEVERITY_POINTS == {"critical": 40, "high": 20, "medium": 10, "low": 5}
    s = score([mk("high", "kerberos"), mk("low", "kerberos")])
    assert s["categories"]["kerberos"] == 25


def test_category_cap():
    s = score([mk("critical", "privileged")] * 4)
    assert s["categories"]["privileged"] == 100


def test_global_formula():
    # categories: privileged 100, others 0 -> 0.5*100 + 0.5*20 = 60
    s = score([mk("critical", "privileged")] * 3)
    assert s["global"] == 60
    # 40 + 20 in two categories: max 40, mean 12 -> 26
    s = score([mk("critical", "privileged"), mk("high", "trusts")])
    assert s["global"] == round(0.5 * 40 + 0.5 * (60 / 5))


def test_global_never_exceeds_100():
    allf = [mk("critical", c) for c in CATEGORIES for _ in range(5)]
    assert score(allf)["global"] == 100


def test_object_count_does_not_change_score():
    a, b = mk("high", "accounts"), mk("high", "accounts")
    b.affected = 500
    assert score([a]) == score([b])


@pytest.mark.parametrize("val,name", [(0, "faible"), (20, "faible"), (21, "modéré"),
                                      (50, "modéré"), (51, "élevé"), (76, "critique"), (100, "critique")])
def test_levels(val, name):
    assert level(val) == name


def test_agrisouss_scores(vuln, hard, cfg):
    from adaudit.model import load_export
    from conftest import QUICK
    sv = score(list(fired(vuln, cfg).values()))
    sq = score(list(fired(load_export(QUICK), cfg).values()))
    sh = score(list(fired(hard, cfg).values()))
    assert sv["global"] == 90 and sq["global"] == 74 and sh["global"] == 0
    assert sv["global"] > sq["global"] > sh["global"]


def test_plan_buckets_and_order():
    fs = [mk("low", "accounts", "quick", "AD-A-001"), mk("critical", "accounts", "quick", "AD-B-002"),
          mk("high", "kerberos", "90d", "AD-C-003")]
    plan = build_plan(fs)
    assert [b["bucket"] for b in plan] == ["quick", "30d", "90d"]
    assert [a["id"] for a in plan[0]["actions"]] == ["AD-B-002", "AD-A-001"]
    assert plan[1]["actions"] == [] and plan[2]["actions"][0]["id"] == "AD-C-003"


def test_quickwins_export_only_lacks_quick_findings(vuln, cfg):
    from adaudit.model import load_export
    from conftest import QUICK
    before = fired(vuln, cfg)
    after = fired(load_export(QUICK), cfg)
    assert all(f.effort == "quick" for k, f in before.items() if k not in after)
    assert not any(f.effort == "quick" for f in after.values())
