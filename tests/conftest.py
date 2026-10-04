import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from adaudit.config import load_config  # noqa: E402
from adaudit.engine import run_checks  # noqa: E402
from adaudit.model import Directory, load_export  # noqa: E402

DATA = os.path.join(ROOT, "data")
VULN = os.path.join(DATA, "agrisouss_vulnerable.json")
QUICK = os.path.join(DATA, "agrisouss_quickwins.json")
HARD = os.path.join(DATA, "agrisouss_hardened.json")

# fake secrets planted in the synthetic descriptions - must never appear in any output
PLANTED_SECRETS = ["Souss@2023", "Scan2022"]

MINIMAL = {
    "schemaVersion": "1.0",
    "exportedAt": "2026-09-30T08:00:00Z",
    "domain": {"name": "test.local"},
    "passwordPolicy": {"minPasswordLength": 14, "complexityEnabled": True,
                       "passwordHistoryCount": 24, "lockoutThreshold": 5,
                       "lockoutDurationMinutes": 15, "lockoutObservationWindowMinutes": 15},
    "krbtgt": {"pwdLastSet": "2026-08-01T00:00:00Z"},
    "users": [
        {"samAccountName": "adm.a", "enabled": True, "lastLogon": "2026-09-29T08:00:00Z",
         "pwdLastSet": "2026-06-01T00:00:00Z", "adminCount": 1, "accountNotDelegated": True},
        {"samAccountName": "u.one", "enabled": True, "lastLogon": "2026-09-28T08:00:00Z",
         "pwdLastSet": "2026-05-01T00:00:00Z", "description": "Comptabilite - Agadir"},
    ],
    "groups": [
        {"name": "Domain Admins", "members": [{"type": "user", "name": "adm.a"}]},
        {"name": "Administrators", "members": [{"type": "group", "name": "Domain Admins"}]},
        {"name": "Protected Users", "members": [{"type": "user", "name": "adm.a"}]},
    ],
    "computers": [
        {"name": "DC01", "enabled": True, "operatingSystem": "Windows Server 2022 Standard",
         "isDomainController": True, "trustedForDelegation": True},
        {"name": "PC01", "enabled": True, "operatingSystem": "Windows 11 Pro",
         "lapsPasswordSet": True},
    ],
    "gpoSummary": {"lapsDeployed": True, "smbSigningRequiredDCs": True,
                   "smbSigningRequiredMembers": True, "llmnrDisabled": True,
                   "netbiosDisabled": True, "lmCompatibilityLevel": 5},
    "trusts": [],
}


@pytest.fixture
def minimal():
    return copy.deepcopy(MINIMAL)


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def vuln():
    return load_export(VULN)


@pytest.fixture(scope="session")
def hard():
    return load_export(HARD)


def fired(data_or_dir, cfg):
    d = data_or_dir if isinstance(data_or_dir, Directory) else Directory(data_or_dir)
    return {f.id: f for f in run_checks(d, cfg)}


def write_json(tmp_path, data, name="export.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)
