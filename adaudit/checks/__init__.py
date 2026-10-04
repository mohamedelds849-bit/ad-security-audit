"""Check plugins. Every module in this package is imported by engine.all_checks().

Reference conventions used in `references`:
- "ANSSI vuln_xxx" = identifier of the ANSSI / CERT-FR "Points de contrôle Active Directory"
  (https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html, identifiers read on 2026-10-03).
- CIS = CIS Microsoft Windows Server Benchmark; section numbers change between versions, so
  only the setting name is given.
- MITRE ATT&CK IDs/names were checked against ATT&CK v19.2 (attack.mitre.org, 2026-10-03).
"""
from __future__ import annotations

import re

KRBTGT = "krbtgt"


def enabled_users(d):
    """Enabled user objects, without the krbtgt service account."""
    return [u for u in d.users if u["enabled"] and u["samAccountName"].lower() != KRBTGT]


def privileged_map(d, cfg):
    """{lower-case sam: set(groups)} restricted to enabled users."""
    pmap = d.privileged_users(cfg.get("privileged_groups", []))
    out = {}
    for name, groups in pmap.items():
        u = d.user(name)
        if u is not None and u["enabled"] and name != KRBTGT:
            out[name] = groups
    return out


def label(u) -> str:
    return u["samAccountName"]


def fmt_groups(groups) -> str:
    return ", ".join(sorted(groups))


def compile_hint_regex(patterns):
    """Keyword followed by a value: 'mdp: X', 'pwd=X', 'password X'."""
    words = "|".join(re.escape(p) for p in sorted(patterns, key=len, reverse=True))
    return re.compile(r"(?i)(?<![a-z])(" + words + r")(?![a-z])\s*[:=]?\s*(\S+)")
