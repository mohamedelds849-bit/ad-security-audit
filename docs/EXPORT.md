# Producing an export from your own domain

> **Authorization.** Only run these commands on a domain you administer, or with the
> written authorization of its owner (engagement letter naming the domain, the period and
> the people involved). Even a read-only inventory reveals the structure of the
> organisation. The JSON file is **confidential**: keep it encrypted, transfer it only to
> the auditor, delete it when the audit is over.

Everything below is **read-only**: only `Get-*` cmdlets of the built-in `ActiveDirectory`
module (RSAT). No object is modified, no password, hash or LAPS password is read, and no host
other than the domain controller is contacted. A standard domain user account can read
almost all of these attributes; a dedicated, temporary audit account is recommended so that
the activity is traceable.

> Status: the script `tools/Export-ADConfig.ps1` was syntax-checked with the PowerShell
> parser but **has not been run against a real domain** by the author. Review it before use.

## 1. Prerequisites

```powershell
# Windows 10/11: Settings > Optional features > "RSAT: Active Directory Domain Services"
# Windows Server: Install-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory
```

## 2. One-shot script

```powershell
.\tools\Export-ADConfig.ps1 -OutFile .\ad-export.json
python -m adaudit audit .\ad-export.json --html report.html
```

By default the script **redacts** everything that follows `mdp`, `pwd`, `password`, `pass`...
in the description field (`mdp: ********`, up to the end of the description, so that
"password is X" does not leak X), so the export itself never contains such a secret; the
auditor still flags the account. `-KeepDescriptions` disables this (not advised).

## 3. What each section comes from

| Section | Read-only cmdlet | Notes |
|---|---|---|
| `domain` | `Get-ADDomain` | DNSRoot, NetBIOSName, DomainMode |
| `passwordPolicy` | `Get-ADDefaultDomainPasswordPolicy` | lengths, history, lockout |
| `krbtgt` | `Get-ADUser krbtgt -Properties PasswordLastSet` | date only |
| `users` | `Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,adminCount,servicePrincipalName,DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,AccountNotDelegated,Description,whenCreated` | `isBuiltinGuest` = SID ends with -501 |
| `groups` | `Get-ADGroup -Filter *` + `Get-ADGroupMember` (direct members) | well-known groups renamed to English by SID, other groups named by sAMAccountName (unique) |
| `computers` | `Get-ADComputer -Filter * -Properties Enabled,OperatingSystem,OperatingSystemVersion,LastLogonDate,TrustedForDelegation,PrimaryGroupID,msLAPS-PasswordExpirationTime,ms-Mcs-AdmPwdExpirationTime` | only the LAPS **expiration time** |
| `managedServiceAccounts` | `Get-ADServiceAccount -Filter *` | gMSA names and SPN |
| `trusts` | `Get-ADTrust -Filter *` | SIDFilteringQuarantined, SelectiveAuthentication; intra-forest (parent-child / tree-root) trusts are skipped: SID filtering does not apply inside a forest |

Spot checks you can run by hand (all read-only):

```powershell
Get-ADDefaultDomainPasswordPolicy
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object SamAccountName, objectClass
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object SamAccountName
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Select-Object Name
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
Get-ADTrust -Filter * | Select-Object Target, Direction, SIDFilteringQuarantined
```

## 4. Completing `gpoSummary` by hand

These values depend on GPOs and on how they are linked, which the AD cmdlets above do not
resolve reliably. The script writes `null`; the auditor refuses the file until you replace
each `null` by a real value after a GPO review (Group Policy Management Console, or the
read-only `Get-GPOReport -All -ReportType Html -Path gpo.html` of the GroupPolicy module):

| Field | Look for this setting | Value |
|---|---|---|
| `smbSigningRequiredDCs` | "Microsoft network server: Digitally sign communications (always)" in the policy linked to *Domain Controllers* | true if Enabled |
| `smbSigningRequiredMembers` | same setting in policies linked to server / workstation OUs | true if Enabled everywhere |
| `llmnrDisabled` | Computer Config > Admin Templates > Network > DNS Client > "Turn off multicast name resolution" | true if Enabled |
| `netbiosDisabled` | DHCP option 001 (Microsoft) = 2, or NIC setting via script | true if disabled everywhere |
| `lmCompatibilityLevel` | "Network security: LAN Manager authentication level" | 0-5 (5 = NTLMv2 only, refuse LM & NTLM). "Not defined" = OS default, 3 on current Windows: write 3, not 5 |

Being honest in this section matters: a `true` you are not sure about hides a risk.
When in doubt, write the insecure value and verify later.

## 5. Handling the file

- Store it outside synced folders, encrypted (BitLocker / 7-Zip AES-256).
- Never commit it to Git (`.gitignore` the folder) and never upload it to an online tool.
- Delete it, and the reports derived from it, at the end of the engagement.
