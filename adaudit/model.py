"""Load and validate an Active Directory configuration export (see docs/SCHEMA.md).

The auditor never talks to a domain controller: it only reads a JSON file that an
administrator produced from their own domain with read-only cmdlets. This module turns
that file into a validated `Directory` object with a few helpers (group expansion,
age computation) used by the checks.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
MAX_FILE_BYTES = 50 * 1024 * 1024  # refuse absurdly large inputs instead of hanging


class SchemaError(ValueError):
    """Raised when the export does not follow docs/SCHEMA.md."""


# ---------------------------------------------------------------------------
# Field specifications: name -> (type or tuple of types, required, default)
# "date" means an ISO-8601 string or null.
# ---------------------------------------------------------------------------
DATE = "date"
STR_LIST = "str_list"

DOMAIN_FIELDS = {
    "name": (str, True, None),
    "netbiosName": (str, False, ""),
    "functionalLevel": (str, False, ""),
}
POLICY_FIELDS = {
    "minPasswordLength": (int, True, None),
    "complexityEnabled": (bool, True, None),
    "passwordHistoryCount": (int, True, None),
    "maxPasswordAgeDays": (int, False, 0),
    "minPasswordAgeDays": (int, False, 0),
    "reversibleEncryptionEnabled": (bool, False, False),
    "lockoutThreshold": (int, True, None),
    "lockoutDurationMinutes": (int, False, 0),
    "lockoutObservationWindowMinutes": (int, False, 0),
}
USER_FIELDS = {
    "samAccountName": (str, True, None),
    "displayName": (str, False, ""),
    "enabled": (bool, True, None),
    "lastLogon": (DATE, False, None),
    "pwdLastSet": (DATE, False, None),
    "whenCreated": (DATE, False, None),
    "passwordNeverExpires": (bool, False, False),
    "passwordNotRequired": (bool, False, False),
    "adminCount": (int, False, 0),
    "servicePrincipalNames": (STR_LIST, False, []),
    "doesNotRequirePreAuth": (bool, False, False),
    "trustedForDelegation": (bool, False, False),
    "trustedToAuthForDelegation": (bool, False, False),
    "accountNotDelegated": (bool, False, False),
    "description": (str, False, ""),
    "isBuiltinGuest": (bool, False, False),
}
GROUP_FIELDS = {
    "name": (str, True, None),
    "members": (list, False, []),
}
MEMBER_FIELDS = {
    "type": (str, True, None),
    "name": (str, True, None),
}
COMPUTER_FIELDS = {
    "name": (str, True, None),
    "enabled": (bool, True, None),
    "operatingSystem": (str, False, ""),
    "operatingSystemVersion": (str, False, ""),
    "lastLogon": (DATE, False, None),
    "isDomainController": (bool, False, False),
    "trustedForDelegation": (bool, False, False),
    "lapsPasswordSet": (bool, False, False),
}
GMSA_FIELDS = {
    "name": (str, True, None),
    "servicePrincipalNames": (STR_LIST, False, []),
}
GPO_FIELDS = {
    "lapsDeployed": (bool, True, None),
    "smbSigningRequiredDCs": (bool, True, None),
    "smbSigningRequiredMembers": (bool, True, None),
    "llmnrDisabled": (bool, True, None),
    "netbiosDisabled": (bool, True, None),
    "lmCompatibilityLevel": (int, True, None),
}
TRUST_FIELDS = {
    "target": (str, True, None),
    "direction": (str, False, "Bidirectional"),
    "trustType": (str, False, "External"),
    "sidFilteringEnabled": (bool, True, None),
    "selectiveAuthentication": (bool, False, False),
}
MEMBER_TYPES = {"user", "group", "computer", "gmsa"}


def parse_date(value: str | None, where: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SchemaError(f"{where}: date attendue (chaîne ISO-8601 ou null)")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"{where}: date invalide {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _check_fields(obj, spec: dict, where: str) -> dict:
    """Validate one JSON object against a field spec, return a normalised copy."""
    if not isinstance(obj, dict):
        raise SchemaError(f"{where}: objet JSON attendu, reçu {type(obj).__name__}")
    out = {}
    for name, (ftype, required, default) in spec.items():
        if name not in obj or (obj[name] is None and ftype is not DATE):
            if required:
                raise SchemaError(f"{where}: champ obligatoire manquant '{name}'")
            out[name] = list(default) if isinstance(default, list) else default
            continue
        value = obj[name]
        loc = f"{where}.{name}"
        if ftype is DATE:
            out[name] = parse_date(value, loc)
        elif ftype is STR_LIST:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise SchemaError(f"{loc}: liste de chaînes attendue")
            out[name] = list(value)
        elif ftype is int:
            # bool is a subclass of int in Python: refuse it explicitly
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaError(f"{loc}: entier attendu, reçu {value!r}")
            out[name] = value
        elif not isinstance(value, ftype):
            raise SchemaError(f"{loc}: type {ftype.__name__} attendu, reçu {type(value).__name__}")
        else:
            out[name] = value
    return out


def _check_list(data: dict, key: str, spec: dict, unique_key: str) -> list[dict]:
    raw = data.get(key, [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise SchemaError(f"{key}: liste attendue")
    items, seen = [], set()
    for i, obj in enumerate(raw):
        item = _check_fields(obj, spec, f"{key}[{i}]")
        k = item[unique_key].lower()
        if k in seen:
            raise SchemaError(f"{key}[{i}]: doublon '{item[unique_key]}'")
        seen.add(k)
        items.append(item)
    return items


class Directory:
    """Validated, read-only view of the export with helpers for the checks."""

    def __init__(self, data: dict):
        if not isinstance(data, dict):
            raise SchemaError("la racine du fichier doit être un objet JSON")
        version = data.get("schemaVersion")
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            raise SchemaError(f"schemaVersion non supportée: {version!r} (attendu: 1.0)")
        self.exported_at = parse_date(data.get("exportedAt"), "exportedAt")
        if self.exported_at is None:
            raise SchemaError("champ obligatoire manquant 'exportedAt'")
        for section in ("domain", "passwordPolicy", "gpoSummary", "krbtgt"):
            if section not in data:
                raise SchemaError(f"section obligatoire manquante '{section}'")
        self.domain = _check_fields(data["domain"], DOMAIN_FIELDS, "domain")
        self.policy = _check_fields(data["passwordPolicy"], POLICY_FIELDS, "passwordPolicy")
        self.gpo = _check_fields(data["gpoSummary"], GPO_FIELDS, "gpoSummary")
        self.krbtgt = _check_fields(data["krbtgt"], {"pwdLastSet": (DATE, True, None)}, "krbtgt")
        if self.krbtgt["pwdLastSet"] is None:
            raise SchemaError("krbtgt.pwdLastSet: date obligatoire")
        self.users = _check_list(data, "users", USER_FIELDS, "samAccountName")
        self.groups = _check_list(data, "groups", GROUP_FIELDS, "name")
        self.computers = _check_list(data, "computers", COMPUTER_FIELDS, "name")
        self.gmsas = _check_list(data, "managedServiceAccounts", GMSA_FIELDS, "name")
        self.trusts = _check_list(data, "trusts", TRUST_FIELDS, "target")
        for g in self.groups:
            members = []
            for j, m in enumerate(g["members"]):
                mm = _check_fields(m, MEMBER_FIELDS, f"groups[{g['name']}].members[{j}]")
                if mm["type"] not in MEMBER_TYPES:
                    raise SchemaError(
                        f"groups[{g['name']}].members[{j}].type: valeur inconnue {mm['type']!r}")
                members.append(mm)
            g["members"] = members
        self._users = {u["samAccountName"].lower(): u for u in self.users}
        self._groups = {g["name"].lower(): g for g in self.groups}

    # -- lookups ----------------------------------------------------------
    def user(self, name: str) -> dict | None:
        return self._users.get(name.lower())

    def group(self, name: str) -> dict | None:
        return self._groups.get(name.lower())

    def age_days(self, dt: datetime | None) -> int | None:
        """Days between a timestamp and the export date (None if never set)."""
        if dt is None:
            return None
        return (self.exported_at - dt).days

    # -- group expansion ----------------------------------------------------
    def expand(self, group_name: str) -> tuple[set[str], list[list[str]]]:
        """Return (effective user names, nested group paths) for a group.

        Nested membership is followed through every level. A `visited` set makes the walk
        safe against membership cycles (A in B in A), which exist in real domains.
        """
        users: set[str] = set()
        nested_paths: list[list[str]] = []
        visited: set[str] = {group_name.lower()}
        todo: list[tuple[str, list[str]]] = [(group_name, [group_name])]
        while todo:  # iterative walk: no recursion limit on deep nesting
            name, path = todo.pop()
            g = self.group(name)
            if g is None:
                continue
            for m in g["members"]:
                if m["type"] == "user":
                    users.add(m["name"].lower())
                elif m["type"] == "group":
                    nested_paths.append(path + [m["name"]])
                    key = m["name"].lower()
                    if key not in visited:
                        visited.add(key)
                        todo.append((m["name"], path + [m["name"]]))
        return users, nested_paths

    def privileged_users(self, privileged_groups: list[str]) -> dict[str, set[str]]:
        """Map user (lower-case name) -> set of privileged groups granting the privilege."""
        result: dict[str, set[str]] = {}
        for gname in privileged_groups:
            if self.group(gname) is None:
                continue
            members, _ = self.expand(gname)
            for u in members:
                result.setdefault(u, set()).add(gname)
        return result


def load_export(path: str) -> Directory:
    """Read a JSON export from disk and validate it. Raises SchemaError on any problem."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SchemaError(f"fichier introuvable ou illisible: {path}") from exc
    if size > MAX_FILE_BYTES:
        raise SchemaError(f"fichier trop volumineux ({size} octets, max {MAX_FILE_BYTES})")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:  # -sig: accept PowerShell BOM
            data = json.load(fh)
    except UnicodeDecodeError as exc:
        raise SchemaError("le fichier n'est pas encodé en UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"JSON invalide (ligne {exc.lineno}, colonne {exc.colno}): {exc.msg}") from exc
    return Directory(data)
