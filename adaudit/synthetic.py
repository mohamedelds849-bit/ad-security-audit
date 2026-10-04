"""Deterministic SYNTHETIC Active Directory exports for the fictional SME "AgriSouss SARL".

All names, accounts, machines and "passwords" below are invented. Nothing comes from a
real company. The same seed always produces byte-identical files, so tests can rely on them.

Three exports are produced from one base:
- agrisouss_vulnerable.json : the domain "as found", with realistic weaknesses
- agrisouss_quickwins.json  : vulnerable + only the "quick win" fixes applied
- agrisouss_hardened.json   : vulnerable + every fix applied (all checks silent)

Each fix is keyed by the check id it remediates, so the quick-wins export is built from the
same `effort` buckets as the remediation plan.
"""
from __future__ import annotations

import copy
import json
import os
import random

SEED = 20261003
EXPORTED_AT = "2026-09-30T08:00:00Z"
DOMAIN = "agrisouss.local"

FIRST = ["Youssef", "Fatima", "Khadija", "Hassan", "Aicha", "Omar", "Salma", "Rachid",
         "Nadia", "Karim", "Imane", "Brahim", "Leila", "Hamid", "Zineb", "Said", "Meryem",
         "Abdellah", "Samira", "Mustapha", "Houda", "Driss", "Siham", "Anas", "Ghizlane",
         "Yassine", "Hajar", "Ayoub", "Soukaina", "Hicham"]
LAST = ["Benali", "Idrissi", "Bakkali", "Alaoui", "Berrada", "Chraibi", "Haddad",
        "Ait Lahcen", "Ouali", "Bouzid", "Lahlou", "Naciri", "Zahiri", "Ait Baha", "Belkadi",
        "Mansouri", "Ouazzani", "Rami", "Sabri", "Tahiri", "Ziani", "Moussaoui", "Kettani"]
DEPTS = ["Comptabilite", "RH", "Logistique", "Production", "Commercial", "Qualite", "Export"]
SITES = ["Agadir", "Taroudant"]


def _d(y, m, day, h=9):
    return f"{y:04d}-{m:02d}-{day:02d}T{h:02d}:00:00Z"


def _user(sam, display, *, enabled=True, last=None, pwd=None, created=_d(2022, 1, 10), **kw):
    u = {
        "samAccountName": sam, "displayName": display, "enabled": enabled,
        "lastLogon": last, "pwdLastSet": pwd, "whenCreated": created,
        "passwordNeverExpires": False, "passwordNotRequired": False, "adminCount": 0,
        "servicePrincipalNames": [], "doesNotRequirePreAuth": False,
        "trustedForDelegation": False, "trustedToAuthForDelegation": False,
        "accountNotDelegated": False, "description": "", "isBuiltinGuest": False,
    }
    u.update(kw)
    return u


def _members(*names, kind="user"):
    return [{"type": kind, "name": n} for n in names]


def build_vulnerable() -> dict:
    rng = random.Random(SEED)
    users = [
        _user("Administrator", "Administrateur intégré", last=_d(2026, 9, 28),
              pwd=_d(2017, 4, 3), created=_d(2017, 4, 3), passwordNeverExpires=True, adminCount=1,
              description="Compte d'administration intégré du domaine"),
        _user("Guest", "Invité", enabled=True, last=None, pwd=None, created=_d(2017, 4, 3),
              isBuiltinGuest=True, description="Compte intégré pour l'accès invité"),
        _user("krbtgt", "krbtgt", enabled=False, pwd=_d(2019, 3, 12), created=_d(2017, 4, 3),
              adminCount=1, description="Compte de service du centre de distribution de clés"),
        _user("adm.y.amrani", "Youssef Amrani (admin)", last=_d(2026, 9, 29), pwd=_d(2024, 2, 1),
              adminCount=1, passwordNeverExpires=True, description="Admin domaine - Resp. IT"),
        _user("adm.n.elfassi", "Nadia El Fassi (admin)", last=_d(2026, 9, 25), pwd=_d(2025, 11, 5),
              adminCount=1, description="Admin domaine - Ingenieure systeme"),
        _user("y.amrani", "Youssef Amrani", last=_d(2026, 9, 29), pwd=_d(2026, 6, 1),
              description="Responsable informatique - Agadir"),
        _user("k.ouhadi", "Karim Ouhadi", last=_d(2026, 9, 29), pwd=_d(2026, 3, 14), adminCount=1,
              description="Chef comptable - Agadir"),
        _user("it.prestataire", "Prestataire InfoSouss", last=_d(2025, 6, 2), pwd=_d(2023, 1, 9),
              adminCount=1, passwordNeverExpires=True,
              description="Compte prestataire InfoSouss - mdp: Souss@2023"),
        _user("s.bakkali", "Said Bakkali", last=_d(2026, 9, 27), pwd=_d(2026, 5, 2),
              description="Technicien support - Agadir"),
        _user("o.haddad", "Omar Haddad", last=_d(2026, 9, 26), pwd=_d(2026, 4, 20),
              description="Technicien support - Taroudant"),
        _user("svc_backup", "Service sauvegarde", last=_d(2026, 9, 30), pwd=_d(2019, 6, 18),
              adminCount=1, passwordNeverExpires=True,
              servicePrincipalNames=["BackupSvc/srv-bkp01.agrisouss.local"],
              description="Compte de service logiciel de sauvegarde"),
        _user("svc_sql", "Service SQL Server", last=_d(2026, 9, 30), pwd=_d(2018, 10, 2),
              adminCount=1, passwordNeverExpires=True,
              servicePrincipalNames=["MSSQLSvc/srv-sql01.agrisouss.local:1433",
                                     "MSSQLSvc/srv-sql01.agrisouss.local"],
              description="Compte de service ERP / SQL"),
        _user("svc_web", "Service intranet", last=_d(2026, 9, 30), pwd=_d(2021, 3, 30),
              passwordNeverExpires=True, trustedForDelegation=True,
              servicePrincipalNames=["HTTP/intranet.agrisouss.local"],
              description="Pool IIS intranet"),
        _user("svc_scan", "Copieur RICOH", last=_d(2026, 9, 29), pwd=_d(2022, 2, 7),
              doesNotRequirePreAuth=True, passwordNeverExpires=True,
              description="Scanner RICOH 2e etage - pwd Scan2022"),
        _user("h.idrissi", "Hamid Idrissi", last=_d(2026, 9, 24), pwd=_d(2026, 1, 11),
              doesNotRequirePreAuth=True, description="Ancienne application de pointage"),
        _user("test.user", "Compte de test", last=None, pwd=None, created=_d(2024, 2, 19),
              passwordNotRequired=True, description="Test GPO"),
        _user("r.tazi", "Rachid Tazi", enabled=False, last=_d(2024, 12, 20), pwd=_d(2024, 6, 1),
              adminCount=1, description="Ancien responsable IT (parti en 2025)"),
    ]
    used = {u["samAccountName"] for u in users}
    employees = []
    for i in range(42):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        sam = f"{first[0].lower()}.{last.lower().replace(' ', '')}"
        n = 2
        while sam in used:
            sam = f"{first[0].lower()}.{last.lower().replace(' ', '')}{n}"
            n += 1
        used.add(sam)
        dept, site = rng.choice(DEPTS), rng.choice(SITES)
        stale = i < 5  # five forgotten accounts (left the company, never disabled)
        last_logon = (_d(2025, rng.randint(1, 12), rng.randint(1, 28)) if stale
                      else _d(2026, 9, rng.randint(1, 29)))
        pwd = _d(2026 if not stale else 2024, rng.randint(1, 9), rng.randint(1, 28))
        employees.append(_user(sam, f"{first} {last}", last=last_logon, pwd=pwd,
                               created=_d(rng.randint(2018, 2024), rng.randint(1, 12), 1),
                               description=f"{dept} - {site}"))
    users += employees

    by_dept: dict[str, list[str]] = {}
    for u in employees:
        by_dept.setdefault("GRP-" + u["description"].split(" - ")[0], []).append(u["samAccountName"])
    agadir = [u["samAccountName"] for u in employees if u["description"].endswith("Agadir")]
    taroudant = [u["samAccountName"] for u in employees if u["description"].endswith("Taroudant")]

    groups = [
        {"name": "Domain Admins", "members": _members(
            "Administrator", "adm.y.amrani", "adm.n.elfassi", "k.ouhadi", "it.prestataire",
            "svc_backup") + _members("IT-Support", kind="group")},
        {"name": "Enterprise Admins", "members": _members("Administrator")},
        {"name": "Schema Admins", "members": _members("Administrator")},
        {"name": "Administrators", "members": _members("Administrator", "svc_sql")
            + _members("Domain Admins", "Enterprise Admins", "Prestataires", kind="group")},
        {"name": "Account Operators", "members": []},
        {"name": "Backup Operators", "members": _members("svc_backup")},
        {"name": "Server Operators", "members": []},
        {"name": "Print Operators", "members": []},
        {"name": "DnsAdmins", "members": []},
        {"name": "Group Policy Creator Owners", "members": _members("Administrator")},
        {"name": "Key Admins", "members": []},
        {"name": "Enterprise Key Admins", "members": []},
        {"name": "Protected Users", "members": []},
        {"name": "IT-Support", "members": _members("s.bakkali", "o.haddad")},
        {"name": "Prestataires", "members": _members("it.prestataire")},
        {"name": "GRP-Agadir", "members": _members(*agadir) + _members("GRP-Taroudant", kind="group")},
        {"name": "GRP-Taroudant", "members": _members(*taroudant) + _members("GRP-Agadir", kind="group")},
    ]
    groups += [{"name": g, "members": _members(*sorted(m))} for g, m in sorted(by_dept.items())]

    computers = [
        {"name": "DC01", "enabled": True, "operatingSystem": "Windows Server 2019 Standard",
         "operatingSystemVersion": "10.0 (17763)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": True, "trustedForDelegation": True, "lapsPasswordSet": False},
        {"name": "DC02", "enabled": True, "operatingSystem": "Windows Server 2016 Standard",
         "operatingSystemVersion": "10.0 (14393)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": True, "trustedForDelegation": True, "lapsPasswordSet": False},
        {"name": "SRV-FILE01", "enabled": True, "operatingSystem": "Windows Server 2012 R2 Standard",
         "operatingSystemVersion": "6.3 (9600)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": False, "trustedForDelegation": False, "lapsPasswordSet": False},
        {"name": "SRV-SQL01", "enabled": True, "operatingSystem": "Windows Server 2016 Standard",
         "operatingSystemVersion": "10.0 (14393)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": False, "trustedForDelegation": False, "lapsPasswordSet": False},
        {"name": "SRV-APP01", "enabled": True, "operatingSystem": "Windows Server 2019 Standard",
         "operatingSystemVersion": "10.0 (17763)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": False, "trustedForDelegation": True, "lapsPasswordSet": False},
        {"name": "SRV-BKP01", "enabled": True, "operatingSystem": "Windows Server 2019 Standard",
         "operatingSystemVersion": "10.0 (17763)", "lastLogon": _d(2026, 9, 30),
         "isDomainController": False, "trustedForDelegation": False, "lapsPasswordSet": False},
        {"name": "POS-COMPTA-01", "enabled": True, "operatingSystem": "Windows 7 Professional",
         "operatingSystemVersion": "6.1 (7601)", "lastLogon": _d(2026, 9, 29),
         "isDomainController": False, "trustedForDelegation": False, "lapsPasswordSet": False},
        {"name": "PC-ATELIER-LTSC", "enabled": True,
         "operatingSystem": "Windows 10 Enterprise LTSC 2021", "operatingSystemVersion": "10.0 (19044)",
         "lastLogon": _d(2026, 9, 29), "isDomainController": False,
         "trustedForDelegation": False, "lapsPasswordSet": False},
    ]
    for i in range(1, 29):
        win10 = rng.random() < 0.35
        computers.append({
            "name": f"PC-{rng.choice(['AGA', 'TAR'])}-{i:03d}", "enabled": True,
            "operatingSystem": "Windows 10 Pro" if win10 else "Windows 11 Pro",
            "operatingSystemVersion": "10.0 (19045)" if win10 else "10.0 (26100)",
            "lastLogon": _d(2026, 9, rng.randint(15, 30)), "isDomainController": False,
            "trustedForDelegation": False, "lapsPasswordSet": False,
        })

    return {
        "schemaVersion": "1.0",
        "exportedAt": EXPORTED_AT,
        "_notice": "DONNÉES SYNTHÉTIQUES - entreprise fictive AgriSouss SARL, aucune donnée réelle",
        "domain": {"name": DOMAIN, "netbiosName": "AGRISOUSS", "functionalLevel": "Windows2016Domain"},
        "passwordPolicy": {
            "minPasswordLength": 7, "complexityEnabled": True, "passwordHistoryCount": 5,
            "maxPasswordAgeDays": 0, "minPasswordAgeDays": 0, "reversibleEncryptionEnabled": False,
            "lockoutThreshold": 0, "lockoutDurationMinutes": 0, "lockoutObservationWindowMinutes": 0,
        },
        "krbtgt": {"pwdLastSet": _d(2019, 3, 12)},
        "users": users,
        "groups": groups,
        "computers": computers,
        "managedServiceAccounts": [],
        "gpoSummary": {
            "lapsDeployed": False, "smbSigningRequiredDCs": True, "smbSigningRequiredMembers": False,
            "llmnrDisabled": False, "netbiosDisabled": False, "lmCompatibilityLevel": 2,
        },
        "trusts": [{"target": "souss-logistique.local", "direction": "Bidirectional",
                    "trustType": "External", "sidFilteringEnabled": False,
                    "selectiveAuthentication": False}],
    }


# ------------------------------------------------------------------ fixes by check id
def _u(data, sam):
    return next(u for u in data["users"] if u["samAccountName"] == sam)


def _g(data, name):
    return next(g for g in data["groups"] if g["name"] == name)


ADMINS = ["Administrator", "adm.y.amrani", "adm.n.elfassi"]
PRIV_GROUP_NAMES = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                    "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
                    "DnsAdmins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins"]
DEFAULT_NESTED = {("Administrators", "Domain Admins"), ("Administrators", "Enterprise Admins")}


def fix_pwd_policy(data):
    data["passwordPolicy"].update(minPasswordLength=14, complexityEnabled=True,
                                  passwordHistoryCount=24, reversibleEncryptionEnabled=False,
                                  maxPasswordAgeDays=365, minPasswordAgeDays=1)


def fix_lockout(data):
    data["passwordPolicy"].update(lockoutThreshold=5, lockoutDurationMinutes=15,
                                  lockoutObservationWindowMinutes=15)


def fix_domain_admins(data):
    _g(data, "Domain Admins")["members"] = _members(*ADMINS)
    fix_nested(data)
    fix_priv_spn(data)


def fix_nested(data):
    for g in data["groups"]:
        if g["name"] in PRIV_GROUP_NAMES:
            g["members"] = [m for m in g["members"] if m["type"] != "group"
                            or (g["name"], m["name"]) in DEFAULT_NESTED]


def fix_protect_admins(data):
    _g(data, "Protected Users")["members"] = _members(*ADMINS)
    for sam in ADMINS + ["k.ouhadi", "it.prestataire", "s.bakkali", "o.haddad"]:
        _u(data, sam)["accountNotDelegated"] = True


def fix_priv_never_expires(data):
    for sam in ADMINS + ["it.prestataire", "svc_backup", "svc_sql"]:
        _u(data, sam)["passwordNeverExpires"] = False


def fix_admincount(data):
    """Clear adminCount on accounts that are no longer privileged (run after other fixes)."""
    from .model import Directory
    priv = Directory(data).privileged_users(PRIV_GROUP_NAMES)
    for u in data["users"]:
        if u["samAccountName"].lower() != "krbtgt":
            u["adminCount"] = 1 if u["samAccountName"].lower() in priv else 0


def fix_priv_spn(data):
    for g in data["groups"]:
        if g["name"] in PRIV_GROUP_NAMES:
            g["members"] = [m for m in g["members"]
                            if not (m["type"] == "user" and m["name"] in ("svc_backup", "svc_sql"))]


def fix_loops(data):
    _g(data, "GRP-Taroudant")["members"] = [m for m in _g(data, "GRP-Taroudant")["members"]
                                            if m["type"] != "group"]


def fix_stale(data):
    cutoff = "2026-04-03"  # 180 days before the export date
    for u in data["users"]:
        if u["isBuiltinGuest"] or u["samAccountName"] == "krbtgt" or not u["enabled"]:
            continue
        if (u["lastLogon"] or "0000") < cutoff:
            u["enabled"] = False
            u["description"] = (u["description"] + " [désactivé - revue 2026-10]").strip()


def fix_guest(data):
    for u in data["users"]:
        if u["isBuiltinGuest"]:
            u["enabled"] = False


def fix_descriptions(data):
    _u(data, "it.prestataire")["description"] = "Compte prestataire InfoSouss"
    _u(data, "svc_scan")["description"] = "Scanner RICOH 2e etage"


def fix_passwd_notreqd(data):
    for u in data["users"]:
        u["passwordNotRequired"] = False


def fix_preauth(data):
    for u in data["users"]:
        u["doesNotRequirePreAuth"] = False


def fix_service_accounts(data):
    # svc_sql and svc_backup replaced by gMSAs; svc_web keeps a long, recently rotated secret
    for sam in ("svc_sql", "svc_backup"):
        u = _u(data, sam)
        u["enabled"] = False
        u["servicePrincipalNames"] = []
        u["description"] = "Remplacé par un gMSA (2026-09)"
    _u(data, "svc_web")["pwdLastSet"] = _d(2026, 8, 15)
    data["managedServiceAccounts"] = [
        {"name": "gmsa_sql$", "servicePrincipalNames": ["MSSQLSvc/srv-sql01.agrisouss.local:1433"]},
        {"name": "gmsa_backup$", "servicePrincipalNames": ["BackupSvc/srv-bkp01.agrisouss.local"]},
    ]


def fix_delegation(data):
    for c in data["computers"]:
        if not c["isDomainController"]:
            c["trustedForDelegation"] = False
    for u in data["users"]:
        u["trustedForDelegation"] = False


def fix_krbtgt(data):
    data["krbtgt"]["pwdLastSet"] = _d(2026, 7, 20)
    _u(data, "krbtgt")["pwdLastSet"] = _d(2026, 7, 20)


def fix_laps(data):
    data["gpoSummary"]["lapsDeployed"] = True
    for c in data["computers"]:
        c["lapsPasswordSet"] = not c["isDomainController"]


def fix_obsolete_os(data):
    for c in data["computers"]:
        os_name = c["operatingSystem"]
        if "LTSC" in os_name:
            continue
        if os_name.startswith("Windows Server 2012"):
            c["operatingSystem"], c["operatingSystemVersion"] = "Windows Server 2022 Standard", "10.0 (20348)"
        elif os_name.startswith(("Windows 7", "Windows 10")):
            c["operatingSystem"], c["operatingSystemVersion"] = "Windows 11 Pro", "10.0 (26100)"


def fix_smb(data):
    data["gpoSummary"].update(smbSigningRequiredDCs=True, smbSigningRequiredMembers=True)


def fix_llmnr(data):
    data["gpoSummary"].update(llmnrDisabled=True, netbiosDisabled=True)


def fix_ntlm(data):
    data["gpoSummary"]["lmCompatibilityLevel"] = 5


def fix_trusts(data):
    for t in data["trusts"]:
        t["sidFilteringEnabled"] = True
        t["selectiveAuthentication"] = True


FIXES = {
    "AD-PWD-001": fix_pwd_policy, "AD-PWD-002": fix_lockout,
    "AD-PRIV-001": fix_domain_admins, "AD-PRIV-002": fix_nested,
    "AD-PRIV-003": fix_protect_admins, "AD-PRIV-004": fix_priv_never_expires,
    "AD-PRIV-005": fix_admincount, "AD-PRIV-006": fix_priv_spn, "AD-PRIV-007": fix_loops,
    "AD-ACC-001": fix_stale, "AD-ACC-002": fix_guest, "AD-ACC-003": fix_descriptions,
    "AD-ACC-004": fix_passwd_notreqd, "AD-KRB-001": fix_preauth,
    "AD-KRB-002": fix_service_accounts, "AD-KRB-003": fix_delegation, "AD-KRB-004": fix_krbtgt,
    "AD-INF-001": fix_laps, "AD-INF-002": fix_obsolete_os, "AD-INF-003": fix_smb,
    "AD-INF-004": fix_llmnr, "AD-INF-005": fix_ntlm, "AD-TRU-001": fix_trusts,
}


def apply_fixes(data: dict, buckets: set[str]) -> dict:
    """Return a copy of `data` with the fixes of checks whose effort is in `buckets`."""
    from .engine import all_checks
    out = copy.deepcopy(data)
    efforts = {c.id: c.effort for c in all_checks()}
    for check_id in sorted(FIXES):
        if check_id != "AD-PRIV-005" and efforts[check_id] in buckets:
            FIXES[check_id](out)
    # adminCount depends on the final group membership: always recomputed last
    if efforts["AD-PRIV-005"] in buckets:
        fix_admincount(out)
    return out


def build_all() -> dict[str, dict]:
    vuln = build_vulnerable()
    quick = apply_fixes(vuln, {"quick"})
    hard = apply_fixes(vuln, {"quick", "30d", "90d"})
    quick["_notice"] = vuln["_notice"] + " - état après quick wins"
    hard["_notice"] = vuln["_notice"] + " - état durci"
    return {"agrisouss_vulnerable.json": vuln, "agrisouss_quickwins.json": quick,
            "agrisouss_hardened.json": hard}


def dumps(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def write_all(out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name, data in build_all().items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dumps(data))
        paths.append(path)
    return paths
