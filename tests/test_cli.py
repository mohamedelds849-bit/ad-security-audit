"""CLI, outputs (JSON / HTML / compare), safety of the rendered report, config, generator."""
import json
import os
import subprocess
import sys

import pytest

from adaudit.cli import main
from adaudit.config import ConfigError, load_config
from adaudit.synthetic import build_all, dumps
from conftest import DATA, HARD, PLANTED_SECRETS, QUICK, ROOT, VULN, write_json


def test_audit_writes_outputs(tmp_path, capsys):
    j, h = tmp_path / "r.json", tmp_path / "sub" / "r.html"
    assert main(["audit", VULN, "--json", str(j), "--html", str(h)]) == 0
    out = capsys.readouterr().out
    assert "SCORE DE RISQUE GLOBAL : 90/100" in out
    rep = json.loads(j.read_text(encoding="utf-8"))
    assert rep["score"]["global"] == 90 and rep["checks_run"] == 23
    assert len(rep["findings"]) == 23 and {b["bucket"] for b in rep["plan"]} == {"quick", "30d", "90d"}
    assert h.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_fail_on(capsys):
    assert main(["audit", VULN, "--quiet", "--fail-on", "critical"]) == 1
    assert main(["audit", HARD, "--quiet", "--fail-on", "low"]) == 0


def test_malformed_input_exit_2(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{oops", encoding="utf-8")
    assert main(["audit", str(p)]) == 2
    assert "erreur" in capsys.readouterr().err


def test_missing_file_exit_2(tmp_path, capsys):
    assert main(["audit", str(tmp_path / "nope.json")]) == 2


def test_bad_config_exit_2(tmp_path, capsys):
    c = tmp_path / "c.yaml"
    c.write_text("thresholds: [1, 2", encoding="utf-8")
    assert main(["audit", VULN, "--config", str(c)]) == 2


def test_compare(tmp_path, capsys):
    j, h = tmp_path / "c.json", tmp_path / "c.html"
    assert main(["compare", VULN, HARD, "--json", str(j), "--html", str(h)]) == 0
    out = capsys.readouterr().out
    assert "DELTA : -90" in out
    c = json.loads(j.read_text(encoding="utf-8"))
    assert c["delta"] == -90 and len(c["fixed"]) == 23 and c["new"] == [] and c["same_domain"]
    assert "-90" in h.read_text(encoding="utf-8")


def test_compare_quickwins(capsys):
    assert main(["compare", VULN, QUICK]) == 0
    assert "DELTA : -16" in capsys.readouterr().out


def test_compare_other_domain_warns(tmp_path, minimal, capsys):
    assert main(["compare", VULN, write_json(tmp_path, minimal)]) == 0
    assert "pas le même domaine" in capsys.readouterr().out


def test_list_checks(capsys):
    assert main(["list-checks"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 23


def test_module_entrypoint_runs():
    r = subprocess.run([sys.executable, "-m", "adaudit", "audit", HARD, "--quiet"],
                       cwd=ROOT, capture_output=True)
    assert r.returncode == 0


# ------------------------------------------------------------------ output safety
@pytest.fixture(scope="module")
def all_outputs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("out")
    j, h = tmp / "r.json", tmp / "r.html"
    main(["audit", VULN, "--json", str(j), "--html", str(h), "--quiet"])
    return j.read_text(encoding="utf-8"), h.read_text(encoding="utf-8")


@pytest.mark.parametrize("secret", PLANTED_SECRETS)
def test_planted_secrets_never_leak(secret, all_outputs, capsys):
    main(["audit", VULN])
    console = capsys.readouterr().out
    for text in (*all_outputs, console):
        assert secret not in text


def test_html_is_standalone(all_outputs):
    html = all_outputs[1]
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html  # no CDN, no external resource
    assert "Content-Security-Policy" in html


def test_html_escapes_hostile_values(tmp_path, minimal):
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
    minimal["domain"]["name"] = evil
    minimal["users"].append({"samAccountName": evil, "enabled": True,
                             "doesNotRequirePreAuth": True,
                             "lastLogon": "2026-09-20T00:00:00Z"})
    h = tmp_path / "e.html"
    assert main(["audit", write_json(tmp_path, minimal), "--html", str(h), "--quiet"]) == 0
    html = h.read_text(encoding="utf-8")
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


# ------------------------------------------------------------------ config
def test_config_override_changes_result(tmp_path, capsys):
    c = tmp_path / "c.yaml"
    c.write_text("thresholds:\n  max_domain_admins: 10\n", encoding="utf-8")
    j = tmp_path / "r.json"
    main(["audit", VULN, "--config", str(c), "--json", str(j), "--quiet"])
    ids = {f["id"] for f in json.loads(j.read_text(encoding="utf-8"))["findings"]}
    assert "AD-PRIV-001" not in ids


@pytest.mark.parametrize("text", ["thresholds:\n  stale_days: -1\n",
                                  "thresholds:\n  stale_days: abc\n",
                                  "privileged_groups: Domain Admins\n",
                                  "- just\n- a list\n",
                                  "!!python/object/apply:os.system ['echo hi']\n"])
def test_invalid_config(tmp_path, text):
    c = tmp_path / "c.yaml"
    c.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(c))


# ------------------------------------------------------------------ synthetic data
def test_generator_is_deterministic_and_committed_data_in_sync():
    first, second = build_all(), build_all()
    assert first == second
    for name, data in first.items():
        with open(os.path.join(DATA, name), encoding="utf-8") as fh:
            assert fh.read() == dumps(data), f"{name} est désynchronisé : relancer 'generate'"


def test_generate_command(tmp_path, capsys):
    assert main(["generate", "--out", str(tmp_path)]) == 0
    assert sorted(os.listdir(tmp_path)) == sorted(build_all())


def test_synthetic_marker_present():
    for name in build_all():
        with open(os.path.join(DATA, name), encoding="utf-8") as fh:
            assert "DONNÉES SYNTHÉTIQUES" in json.load(fh)["_notice"]
