# Export schema (version 1.0)

`ad-security-audit` reads ONE JSON file describing the configuration of an Active Directory
domain. The file is produced by an administrator with read-only cmdlets (see
[EXPORT.md](EXPORT.md)) or by the synthetic generator (`python -m adaudit generate`).
Validation is done by `adaudit/model.py`; any violation stops the audit with exit code 2 and a
message naming the faulty field (e.g. `users[3].enabled: type bool attendu`).

General rules
- Encoding UTF-8 (a UTF-8 BOM is accepted, PowerShell 5.1 writes one). Max size 50 MB.
- Dates: ISO-8601 strings (`2026-09-30T08:00:00Z`) or `null` (= never). A date without a
  time zone is treated as UTC. All ages are computed relative to `exportedAt`, never to the
  current clock, so an audit is reproducible.
- `int` fields refuse booleans (`true` is not 1); password-policy integers must be >= 0 and
  `lmCompatibilityLevel` must be in 0-5. Unknown extra fields are ignored
  (e.g. `_notice`).
- Names are compared case-insensitively. Duplicate `samAccountName`, group `name`, computer
  `name` or trust `target` are rejected.

## Root

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `schemaVersion` | string | yes | must be `"1.0"` |
| `exportedAt` | date | yes | when the export was taken; reference for every age |
| `domain` | object | yes | `name` (DNS name, req.), `netbiosName`, `functionalLevel` |
| `passwordPolicy` | object | yes | Default Domain Policy, see below |
| `krbtgt` | object | yes | `pwdLastSet` (date, req., not null) |
| `users` | array | no | user objects |
| `groups` | array | no | groups with DIRECT members |
| `computers` | array | no | computer objects |
| `managedServiceAccounts` | array | no | gMSA: `name`, `servicePrincipalNames` |
| `gpoSummary` | object | yes | GPO-level hardening flags |
| `trusts` | array | no | domain / forest trusts |

## passwordPolicy

| Field | Type | Req. | Source (Get-ADDefaultDomainPasswordPolicy) |
|---|---|---|---|
| `minPasswordLength` | int | yes | MinPasswordLength |
| `complexityEnabled` | bool | yes | ComplexityEnabled |
| `passwordHistoryCount` | int | yes | PasswordHistoryCount |
| `maxPasswordAgeDays` | int | no (0) | MaxPasswordAge.Days (0 = never expires) |
| `minPasswordAgeDays` | int | no (0) | MinPasswordAge.Days |
| `reversibleEncryptionEnabled` | bool | no (false) | ReversibleEncryptionEnabled |
| `lockoutThreshold` | int | yes | LockoutThreshold (0 = never locks) |
| `lockoutDurationMinutes` | int | no (0) | LockoutDuration (0 = until an admin unlocks) |
| `lockoutObservationWindowMinutes` | int | no (0) | LockoutObservationWindow |

Fine-Grained Password Policies (PSO) are not modelled in v1.0 (see limits in README).

## users[]

| Field | Type | Default | Source (Get-ADUser property) |
|---|---|---|---|
| `samAccountName` | string | required | SamAccountName |
| `displayName` | string | "" | DisplayName |
| `enabled` | bool | required | Enabled |
| `lastLogon` | date | null | LastLogonDate = `lastLogonTimestamp` (replicated, may lag ~14 days; the non-replicated `lastLogon` is NOT used) |
| `pwdLastSet` | date | null | PasswordLastSet |
| `whenCreated` | date | null | whenCreated |
| `passwordNeverExpires` | bool | false | PasswordNeverExpires (UAC 0x10000) |
| `passwordNotRequired` | bool | false | PasswordNotRequired (UAC 0x20) |
| `adminCount` | int | 0 | adminCount (1 = set by SDProp) |
| `servicePrincipalNames` | string[] | [] | servicePrincipalName |
| `doesNotRequirePreAuth` | bool | false | DoesNotRequirePreAuth (UAC 0x400000) |
| `trustedForDelegation` | bool | false | TrustedForDelegation = unconstrained (UAC 0x80000) |
| `trustedToAuthForDelegation` | bool | false | TrustedToAuthForDelegation (exported, not checked in v1.0) |
| `accountNotDelegated` | bool | false | AccountNotDelegated = "sensitive and cannot be delegated" |
| `description` | string | "" | Description (values after "mdp/pwd/password..." should be redacted at export) |
| `isBuiltinGuest` | bool | false | true when the SID ends with `-501` |

The `krbtgt` user may appear in `users`; checks ignore it except through the `krbtgt` section.

## groups[]

```json
{"name": "Domain Admins", "members": [{"type": "user", "name": "adm.y.amrani"},
                                      {"type": "group", "name": "IT-Support"}]}
```

- `members` lists DIRECT members only; the auditor expands nesting itself (cycle-safe,
  iterative, no depth limit).
- `type` is one of `user`, `group`, `computer`, `gmsa`. For `user` the `name` is the
  `samAccountName`; for `group` it is the group `name` (the export script uses the
  group's sAMAccountName, unique in the domain, for non-well-known groups).
- Well-known privileged groups MUST use their English canonical names (`Domain Admins`,
  `Administrators`, `Protected Users`...), whatever the Windows language. The export script
  maps them by well-known SID / RID (512, 518, 519, 520, 525, 526, 527, S-1-5-32-544/548/549/550/551).
  `DnsAdmins` has no fixed RID and keeps its real name.

## computers[]

| Field | Type | Default | Source (Get-ADComputer) |
|---|---|---|---|
| `name` | string | required | Name |
| `enabled` | bool | required | Enabled |
| `operatingSystem` | string | "" | OperatingSystem (e.g. `Windows Server 2019 Standard`) |
| `operatingSystemVersion` | string | "" | OperatingSystemVersion |
| `lastLogon` | date | null | LastLogonDate |
| `isDomainController` | bool | false | PrimaryGroupID 516 (DC) or 521 (RODC) |
| `trustedForDelegation` | bool | false | TrustedForDelegation |
| `lapsPasswordSet` | bool | false | presence of `msLAPS-PasswordExpirationTime` or `ms-Mcs-AdmPwdExpirationTime` (the password itself is never read) |

## gpoSummary (all required, filled from a GPO review)

| Field | Type | Secure value | GPO setting |
|---|---|---|---|
| `lapsDeployed` | bool | true | a LAPS policy is linked to the computer OUs |
| `smbSigningRequiredDCs` | bool | true | "Microsoft network server: Digitally sign communications (always)" on DCs |
| `smbSigningRequiredMembers` | bool | true | same setting on member servers / workstations |
| `llmnrDisabled` | bool | true | "Turn off multicast name resolution" = Enabled |
| `netbiosDisabled` | bool | true | NetBIOS over TCP/IP disabled (DHCP option / NIC setting) |
| `lmCompatibilityLevel` | int 0-5 (validated) | 5 | "Network security: LAN Manager authentication level" |

## trusts[]

| Field | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | required | trusted domain DNS name |
| `direction` | string | Bidirectional | Inbound / Outbound / Bidirectional (case-insensitive). AD-TRU-001 ignores `Inbound`: SID filtering is applied by the trusting side, i.e. on outbound trusts |
| `trustType` | string | External | External / Forest |
| `sidFilteringEnabled` | bool | required | External: `SIDFilteringQuarantined`; Forest: `not SIDFilteringForestAware` (to verify per case) |
| `selectiveAuthentication` | bool | false | SelectiveAuthentication |

## Minimal valid example

See `MINIMAL` in `tests/conftest.py`: it passes all 23 checks.
