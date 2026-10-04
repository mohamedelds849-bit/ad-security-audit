"""Command-line interface.

    python -m adaudit audit   EXPORT.json [--json OUT] [--html OUT] [--config CFG] [--fail-on SEV]
    python -m adaudit compare BEFORE.json AFTER.json [--json OUT] [--html OUT]
    python -m adaudit list-checks
    python -m adaudit generate [--out DIR]

Exit codes: 0 = OK, 1 = findings at or above --fail-on, 2 = invalid input / config.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .compare import compare, render_compare_console, render_compare_html
from .config import ConfigError, load_config
from .engine import SEVERITIES, all_checks, run_checks
from .model import SchemaError, load_export
from .report import build_report, render_console, render_html, to_json


def _write(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def audit_file(path: str, cfg: dict) -> dict:
    d = load_export(path)
    checks = all_checks()
    findings = run_checks(d, cfg, checks)
    return build_report(d, findings, os.path.basename(path), len(checks))


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adaudit", description="Audit hors ligne d'un export de "
                                "configuration Active Directory (JSON).")
    p.add_argument("--version", action="version", version=f"ad-security-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="auditer un export JSON")
    a.add_argument("export")
    a.add_argument("--config", help="fichier YAML de seuils (surcharge config/default.yaml)")
    a.add_argument("--json", dest="json_out", help="écrire le résultat JSON")
    a.add_argument("--html", dest="html_out", help="écrire le rapport HTML autonome")
    a.add_argument("--quiet", action="store_true", help="pas de résumé console")
    a.add_argument("--fail-on", choices=SEVERITIES,
                   help="code retour 1 si un constat de cette sévérité (ou plus) existe")

    c = sub.add_parser("compare", help="comparer deux exports (avant / après)")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--config")
    c.add_argument("--json", dest="json_out")
    c.add_argument("--html", dest="html_out")

    sub.add_parser("list-checks", help="lister les contrôles disponibles")

    g = sub.add_parser("generate", help="régénérer les exports synthétiques AgriSouss")
    g.add_argument("--out", default="data")
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "list-checks":
            for chk in all_checks():
                mitre = ",".join(t for t, _ in chk.mitre) or "-"
                print(f"{chk.id:<11} {chk.severity:<8} {chk.category:<15} {mitre:<22} {chk.title}")
            return 0
        if args.cmd == "generate":
            from .synthetic import write_all
            for path in write_all(args.out):
                print(f"écrit : {path}")
            return 0
        cfg = load_config(args.config)
        if args.cmd == "audit":
            report = audit_file(args.export, cfg)
            if not args.quiet:
                print(render_console(report))
            if args.json_out:
                _write(args.json_out, to_json(report))
            if args.html_out:
                _write(args.html_out, render_html(report))
            if args.fail_on:
                limit = SEVERITIES.index(args.fail_on)
                if any(SEVERITIES.index(f["severity"]) <= limit for f in report["findings"]):
                    return 1
            return 0
        if args.cmd == "compare":
            before, after = audit_file(args.before, cfg), audit_file(args.after, cfg)
            result = compare(before, after)
            print(render_compare_console(result))
            if args.json_out:
                _write(args.json_out, json.dumps(result, ensure_ascii=False, indent=2))
            if args.html_out:
                _write(args.html_out, render_compare_html(result, __version__))
            return 0
    except (SchemaError, ConfigError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 2
    return 2  # pragma: no cover
