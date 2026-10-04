"""Malformed / hostile input handling for the export loader."""
import json

import pytest

from adaudit import model
from adaudit.model import Directory, SchemaError, load_export
from conftest import write_json


def test_valid_minimal(minimal):
    d = Directory(minimal)
    assert d.domain["name"] == "test.local"
    assert d.user("ADM.A")["adminCount"] == 1  # case-insensitive lookup


@pytest.mark.parametrize("content,msg", [
    ("{not json", "JSON invalide"),
    ("[]", "racine"),
    ('"text"', "racine"),
    ("", "JSON invalide"),
])
def test_bad_json(tmp_path, content, msg):
    p = tmp_path / "x.json"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(SchemaError, match=msg):
        load_export(str(p))


def test_missing_file(tmp_path):
    with pytest.raises(SchemaError, match="introuvable"):
        load_export(str(tmp_path / "absent.json"))


def test_not_utf8(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b'{"a": "\xff\xfe\xfa"}')
    with pytest.raises(SchemaError, match="UTF-8"):
        load_export(str(p))


def test_utf8_bom_accepted(tmp_path, minimal):
    # Windows PowerShell 5.1 "Out-File -Encoding utf8" writes a BOM
    p = tmp_path / "bom.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps(minimal).encode("utf-8"))
    assert load_export(str(p)).domain["name"] == "test.local"


def test_file_too_large(tmp_path, minimal, monkeypatch):
    monkeypatch.setattr(model, "MAX_FILE_BYTES", 100)
    with pytest.raises(SchemaError, match="volumineux"):
        load_export(write_json(tmp_path, minimal))


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.pop("schemaVersion"), "schemaVersion"),
    (lambda d: d.update(schemaVersion="9.9"), "schemaVersion"),
    (lambda d: d.pop("exportedAt"), "exportedAt"),
    (lambda d: d.update(exportedAt="hier"), "date invalide"),
    (lambda d: d.pop("passwordPolicy"), "passwordPolicy"),
    (lambda d: d.pop("gpoSummary"), "gpoSummary"),
    (lambda d: d["krbtgt"].update(pwdLastSet=None), "krbtgt"),
    (lambda d: d["passwordPolicy"].update(minPasswordLength="14"), "entier"),
    (lambda d: d["passwordPolicy"].update(minPasswordLength=True), "entier"),
    (lambda d: d["passwordPolicy"].pop("lockoutThreshold"), "lockoutThreshold"),
    (lambda d: d["users"][0].pop("samAccountName"), "samAccountName"),
    (lambda d: d["users"][0].update(enabled="yes"), "bool"),
    (lambda d: d["users"][0].update(servicePrincipalNames="HTTP/x"), "liste"),
    (lambda d: d["users"][0].update(lastLogon=12345), "date"),
    (lambda d: d["users"].append(dict(d["users"][0])), "doublon"),
    (lambda d: d.update(users={"a": 1}), "liste"),
    (lambda d: d["users"].append("adm.b"), "objet JSON"),
    (lambda d: d["groups"][0]["members"].append({"type": "printer", "name": "x"}), "type"),
    (lambda d: d["groups"][0]["members"].append({"type": "user"}), "name"),
    (lambda d: d["gpoSummary"].update(lmCompatibilityLevel=None), "lmCompatibilityLevel"),
    (lambda d: d["trusts"].append({"target": "x.local"}), "sidFilteringEnabled"),
    (lambda d: d["gpoSummary"].update(lmCompatibilityLevel=9), "hors plage"),
    (lambda d: d["gpoSummary"].update(lmCompatibilityLevel=-1), "hors plage"),
    (lambda d: d["passwordPolicy"].update(minPasswordLength=-3), "négative"),
])
def test_schema_violations(minimal, mutate, msg):
    mutate(minimal)
    with pytest.raises(SchemaError, match=msg):
        Directory(minimal)


def test_naive_dates_are_utc(minimal):
    minimal["users"][1]["lastLogon"] = "2026-09-28T08:00:00"
    d = Directory(minimal)
    assert d.user("u.one")["lastLogon"].tzinfo is not None


def test_optional_sections_default_empty(minimal):
    for k in ("users", "groups", "computers", "trusts"):
        minimal.pop(k)
    d = Directory(minimal)
    assert d.users == [] and d.trusts == [] and d.gmsas == []


def test_group_cycle_expansion_terminates(minimal):
    minimal["groups"] += [
        {"name": "A", "members": [{"type": "group", "name": "B"}, {"type": "user", "name": "u.one"}]},
        {"name": "B", "members": [{"type": "group", "name": "A"}]},
    ]
    users, paths = Directory(minimal).expand("A")
    assert users == {"u.one"} and len(paths) == 2


def test_deep_nesting_no_recursion_error(minimal, cfg):
    from adaudit.engine import run_checks
    n = 5000  # deeper than Python's default recursion limit
    minimal["groups"] += [{"name": f"G{i}", "members": [{"type": "group", "name": f"G{i+1}"}]}
                          for i in range(n)]
    minimal["groups"].append({"name": f"G{n}", "members": [{"type": "user", "name": "u.one"}]})
    d = Directory(minimal)
    assert d.expand("G0")[0] == {"u.one"}
    run_checks(d, cfg)  # loop detection must not crash either


def test_unknown_group_member_is_ignored(minimal):
    minimal["groups"][0]["members"].append({"type": "group", "name": "DoesNotExist"})
    users, _ = Directory(minimal).expand("Domain Admins")
    assert users == {"adm.a"}


def test_input_not_mutated(minimal):
    before = json.dumps(minimal, sort_keys=True)
    Directory(minimal)
    assert json.dumps(minimal, sort_keys=True) == before
