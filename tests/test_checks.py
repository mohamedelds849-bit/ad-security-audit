"""Per-check tests.

1. every check fires on the vulnerable AgriSouss export and is silent on the hardened one;
2. starting from a minimal clean export, ONE targeted change makes exactly ONE check fire
   (proves each check is isolated and tests its own logic, not a side effect).
"""
import re

import pytest

from adaudit.engine import all_checks
from conftest import fired

ALL_IDS = [c.id for c in all_checks()]


def test_minimal_export_is_clean(minimal, cfg):
    assert fired(minimal, cfg) == {}


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_fires_on_vulnerable(check_id, vuln, cfg):
    f = fired(vuln, cfg)
    assert check_id in f, f"{check_id} devrait se déclencher sur l'export vulnérable"
    assert f[check_id].evidence, "un constat doit toujours avoir des preuves"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_silent_on_hardened(check_id, hard, cfg):
    assert check_id not in fired(hard, cfg)


def _u(data, sam):
    return next(u for u in data["users"] if u["samAccountName"] == sam)


def _add_user(data, sam, **kw):
    u = {"samAccountName": sam, "enabled": True, "lastLogon": "2026-09-20T08:00:00Z",
         "pwdLastSet": "2026-06-01T00:00:00Z"}
    u.update(kw)
    data["users"].append(u)
    return u


def _g(data, name):
    return next(g for g in data["groups"] if g["name"] == name)


def _admin(data, sam, **kw):
    _add_user(data, sam, adminCount=1, accountNotDelegated=True, **kw)
    _g(data, "Domain Admins")["members"].append({"type": "user", "name": sam})
    _g(data, "Protected Users")["members"].append({"type": "user", "name": sam})


MUTATIONS = {
    "AD-PWD-001": lambda d: d["passwordPolicy"].update(minPasswordLength=8),
    "AD-PWD-002": lambda d: d["passwordPolicy"].update(lockoutThreshold=0),
    "AD-PRIV-001": lambda d: [_admin(d, f"adm.{i}") for i in "bcd"],
    "AD-PRIV-002": lambda d: (d["groups"].append({"name": "Helpdesk", "members": []}),
                              _g(d, "Domain Admins")["members"].append({"type": "group", "name": "Helpdesk"})),
    "AD-PRIV-003": lambda d: _u(d, "adm.a").update(accountNotDelegated=False),
    "AD-PRIV-004": lambda d: _u(d, "adm.a").update(passwordNeverExpires=True),
    "AD-PRIV-005": lambda d: _u(d, "u.one").update(adminCount=1),
    "AD-PRIV-006": lambda d: _u(d, "adm.a").update(servicePrincipalNames=["HTTP/x.test.local"]),
    "AD-PRIV-007": lambda d: d["groups"].extend([
        {"name": "A", "members": [{"type": "group", "name": "B"}]},
        {"name": "B", "members": [{"type": "group", "name": "A"}]}]),
    "AD-ACC-001": lambda d: _u(d, "u.one").update(lastLogon="2025-01-01T00:00:00Z"),
    "AD-ACC-002": lambda d: _add_user(d, "Guest", isBuiltinGuest=True, lastLogon="2026-09-01T00:00:00Z"),
    "AD-ACC-003": lambda d: _u(d, "u.one").update(description="Poste RH - mdp: Hunter2!"),
    "AD-ACC-004": lambda d: _u(d, "u.one").update(passwordNotRequired=True),
    "AD-KRB-001": lambda d: _u(d, "u.one").update(doesNotRequirePreAuth=True),
    "AD-KRB-002": lambda d: _add_user(d, "svc_app", servicePrincipalNames=["HTTP/app.test.local"],
                                      pwdLastSet="2020-01-01T00:00:00Z"),
    "AD-KRB-003": lambda d: d["computers"][1].update(trustedForDelegation=True),
    "AD-KRB-004": lambda d: d["krbtgt"].update(pwdLastSet="2025-01-01T00:00:00Z"),
    "AD-INF-001": lambda d: d["computers"][1].update(lapsPasswordSet=False),
    "AD-INF-002": lambda d: d["computers"][1].update(operatingSystem="Windows 7 Professional"),
    "AD-INF-003": lambda d: d["gpoSummary"].update(smbSigningRequiredMembers=False),
    "AD-INF-004": lambda d: d["gpoSummary"].update(llmnrDisabled=False),
    "AD-INF-005": lambda d: d["gpoSummary"].update(lmCompatibilityLevel=3),
    "AD-TRU-001": lambda d: d["trusts"].append({"target": "partner.local", "sidFilteringEnabled": False}),
}


def test_every_check_has_a_mutation():
    assert set(MUTATIONS) == set(ALL_IDS)


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_single_mutation_fires_only_that_check(check_id, minimal, cfg):
    MUTATIONS[check_id](minimal)
    assert set(fired(minimal, cfg)) == {check_id}


# ----------------------------------------------------------------- targeted edge cases
def test_domain_controllers_delegation_is_not_reported(minimal, cfg):
    assert minimal["computers"][0]["trustedForDelegation"] is True  # default for DCs
    assert "AD-KRB-003" not in fired(minimal, cfg)


def test_default_admin_nesting_is_not_reported(minimal, cfg):
    # Administrators contains Domain Admins by default: no AD-PRIV-002
    assert "AD-PRIV-002" not in fired(minimal, cfg)


def test_nested_members_count_as_domain_admins(minimal, cfg):
    minimal["groups"].append({"name": "IT", "members": [
        {"type": "user", "name": n} for n in ("adm.b", "adm.c", "adm.d")]})
    for n in ("adm.b", "adm.c", "adm.d"):
        _add_user(minimal, n)
    _g(minimal, "Domain Admins")["members"].append({"type": "group", "name": "IT"})
    f = fired(minimal, cfg)
    assert "AD-PRIV-001" in f and "4 comptes" in f["AD-PRIV-001"].evidence[0]


def test_disabled_admins_not_counted(minimal, cfg):
    for i in "bcd":
        _admin(minimal, f"adm.{i}")
        _u(minimal, f"adm.{i}")["enabled"] = False
    assert "AD-PRIV-001" not in fired(minimal, cfg)


def test_ltsc_exception(minimal, cfg):
    minimal["computers"][1]["operatingSystem"] = "Windows 10 Enterprise LTSC 2021"
    assert "AD-INF-002" not in fired(minimal, cfg)


def test_obsolete_dc_is_tagged(minimal, cfg):
    minimal["computers"][0]["operatingSystem"] = "Windows Server 2012 R2 Standard"
    assert "CONTRÔLEUR DE DOMAINE" in fired(minimal, cfg)["AD-INF-002"].evidence[0]


def test_krbtgt_user_is_not_an_admincount_orphan(minimal, cfg):
    _add_user(minimal, "krbtgt", enabled=False, adminCount=1)
    assert fired(minimal, cfg) == {}


def test_stale_never_logged_recent_account_is_ok(minimal, cfg):
    _add_user(minimal, "new.hire", lastLogon=None, whenCreated="2026-09-25T00:00:00Z")
    assert "AD-ACC-001" not in fired(minimal, cfg)


def test_stale_boundary(minimal, cfg):
    _u(minimal, "u.one")["lastLogon"] = "2026-04-03T08:00:00Z"  # exactly 180 days
    assert "AD-ACC-001" not in fired(minimal, cfg)
    _u(minimal, "u.one")["lastLogon"] = "2026-04-02T08:00:00Z"  # 181 days
    assert "AD-ACC-001" in fired(minimal, cfg)


def test_preauth_on_privileged_account_is_tagged(minimal, cfg):
    _u(minimal, "adm.a")["doesNotRequirePreAuth"] = True
    assert "PRIVILÉGIÉ" in fired(minimal, cfg)["AD-KRB-001"].evidence[0]


@pytest.mark.parametrize("desc,hit", [
    ("mot de passe : Azerty123", True),
    ("PWD=abc", True),
    ("Password Welcome1", True),
    ("Comptabilite - Agadir", False),
    ("Passage au nouveau ERP", False),       # 'pass' inside a word
    ("Compte de service ERP / SQL", False),
])
def test_description_patterns(desc, hit, minimal, cfg):
    _u(minimal, "u.one")["description"] = desc
    assert ("AD-ACC-003" in fired(minimal, cfg)) is hit


def test_description_value_is_masked(minimal, cfg):
    _u(minimal, "u.one")["description"] = "mdp: TopSecret!42"
    ev = " ".join(fired(minimal, cfg)["AD-ACC-003"].evidence)
    assert "TopSecret" not in ev and "********" in ev


def test_lockout_threshold_too_high(minimal, cfg):
    minimal["passwordPolicy"]["lockoutThreshold"] = 50
    assert "50" in fired(minimal, cfg)["AD-PWD-002"].evidence[0]


def test_ntlm_level_messages(minimal, cfg):
    minimal["gpoSummary"]["lmCompatibilityLevel"] = 1
    assert "clients" in fired(minimal, cfg)["AD-INF-005"].evidence[0]


def test_laps_partial_coverage(minimal, cfg):
    for i in range(2, 22):
        minimal["computers"].append({"name": f"PC{i:02d}", "enabled": True,
                                     "operatingSystem": "Windows 11 Pro", "lapsPasswordSet": True})
    # 1 of 21 members without LAPS = 95.2 % >= 95 % -> OK
    minimal["computers"][1]["lapsPasswordSet"] = False
    assert "AD-INF-001" not in fired(minimal, cfg)
    minimal["computers"][2]["lapsPasswordSet"] = False  # 90.5 %
    assert "AD-INF-001" in fired(minimal, cfg)


@pytest.mark.parametrize("direction,hit", [
    ("Inbound", False), ("Outbound", True), ("Bidirectional", True), ("BiDirectional", True)])
def test_trust_direction(direction, hit, minimal, cfg):
    # SID filtering is applied by the trusting side: an inbound-only trust is not our risk
    minimal["trusts"].append({"target": "p.local", "direction": direction,
                              "sidFilteringEnabled": False})
    assert ("AD-TRU-001" in fired(minimal, cfg)) is hit


def test_metadata_quality():
    for c in all_checks():
        assert re.fullmatch(r"AD-[A-Z]{3,4}-\d{3}", c.id)
        assert c.references, c.id
        assert len(c.why) > 40 and len(c.remediation) > 40, c.id
        for tid, name in c.mitre:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid) and name, c.id
