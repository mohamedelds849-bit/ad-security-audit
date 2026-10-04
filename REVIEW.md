# Security review: ad-security-audit

Reviewer role: senior Active Directory security consultant and Python reviewer.
Date: 2026-10-04. Scope: the whole repository (code, 23 checks, config, synthetic data,
PowerShell export script, docs, README, LEARN.md) and the guide chapter
`guide/chapters/07-ad-security-audit.yaml`.

## Verdict

| Item | Result |
|---|---|
| Technical score | **8.5 / 10** |
| Educational score | **9 / 10** |
| Safety | **OK**: defensive only, export script strictly read-only, secrets masked |
| Consistency | **OK**: claimed scores 90 / 74 / 0 reproduced; test count updated to 174 |
| Final | **APPROVED** |

## What was verified

**Tests and CLI.** `python -m pytest`: 167 passed before the review, **174 passed** after it.
`audit` on vulnerable / quickwins / hardened gives **90 (critique) / 74 (élevé) / 0 (faible)**
with 23 / 14 / 0 findings, the same as README and docs/SCORING.md (74 = 0.5 x 90 + 0.5 x mean
(90, 20, 80, 80, 20)). `compare` gives -90. `generate` rebuilds the committed data files
byte for byte.

**ANSSI IDs.** All 16 identifiers were checked against the live CERT-FR checklist
(cert.ssi.gouv.fr/uploads/ad_checklist.html, downloaded 2026-10-04). Each exists and its
title matches the text quoted in the code: vuln_user_accounts_dormant, vuln_guest,
vuln_dc_obsolete, vuln_trusts_domain_notfiltered, vuln_kerberos_properties_preauth(_priv),
vuln_kerberos_properties_encryption, vuln_delegation_t4d, vuln_krbtgt (> 1 year, level 2),
vuln_privileged_members, vuln_protected_users, vuln_dont_expire_priv,
vuln_password_change_priv (> 3 years), vuln_privileged_members_no_admincount, vuln_spn_priv,
vuln_group_loop.

**MITRE ATT&CK.** All 16 IDs were checked on attack.mitre.org. The names are current,
including the renamed ones: T1557.001 "Name Resolution Poisoning and SMB Relay" and
T1484.002 "Domain or Tenant Policy Modification: Trust Modification".

**AD semantics.** The UAC flags in docs/SCHEMA.md are correct: PASSWD_NOTREQD 0x20,
DONT_EXPIRE_PASSWORD 0x10000, TRUSTED_FOR_DELEGATION 0x80000, NOT_DELEGATED 0x100000,
DONT_REQ_PREAUTH 0x400000. The checks also get these right:
- LastLogonDate (replicated lastLogonTimestamp) is used, not the per-DC lastLogon.
- DCs are detected by PrimaryGroupID 516/521 and excluded from the unconstrained-delegation check.
- The default nesting of Domain Admins and Enterprise Admins in Administrators is excluded.
- krbtgt is excluded from the user checks.
- LmCompatibilityLevel: below 3, clients send LM/NTLMv1. At 3 or 4, DCs still accept NTLMv1. 5 is the target.
- The NTLMv1 audit event is 4624 with "Package Name (NTLM only)".
- The double krbtgt reset waits for the TGT lifetime (10 h) and replication.
- External trusts use netdom /quarantine.
- Both LAPS generations are covered (msLAPS-PasswordExpirationTime and ms-Mcs-AdmPwdExpirationTime). Only the expiration attribute is read, never ms-Mcs-AdmPwd or msLAPS-Password / EncryptedPassword.
- SMB signing, LLMNR and NetBIOS remediation use the correct GPO names, and DHCP option 001 = 2 is correct for NetBIOS.
- Severities are sensible: critical for unconstrained delegation and for SPN accounts in admin groups, low for adminCount orphans and group loops.

**Safety.**
- No exploitation content: no tool names, commands or attack steps anywhere (grep for mimikatz, rubeus, hashcat, impacket, responder and similar returned nothing).
- The PowerShell script only calls Get-AD* cmdlets. There is no Set-/New-AD/Remove-/Add- call, and it has an authorization warning.
- No secret attribute is read.
- The fake secrets planted in the data (`Souss@2023`, `Scan2022`) appear in no report, whether JSON, HTML or console.
- The HTML report escapes every value, has no script and no external resource, and sets a CSP of `default-src 'none'`.
- YAML is loaded with safe_load. There are no network calls.

**Honesty.** The README, LEARN.md (Q3, Q18, section 7), the CV line and the guide chapter all
say that the data is synthetic, that the PowerShell script has never been run on a real
domain, and that the project was built with AI assistance. Nowhere does it claim to have
audited a real company.

## Problems found

| # | Severity | Problem | Status |
|---|---|---|---|
| 1 | Medium | AD-TRU-001 flagged **inbound-only** trusts. SID filtering is enforced by the trusting side, so it only concerns our outbound trusts (ANSSI: "approbation **sortante**"). False positive. | Fixed |
| 2 | Medium | Export script: **intra-forest** (parent-child / tree-root) trusts were exported as `External` with `sidFilteringEnabled=false`. Every multi-domain forest would get a false "high" finding. | Fixed (`IntraForest` skipped) |
| 3 | Medium | Export script description masking replaced only the **next word**. `password is Summer2024` or `mdp : Souss 2023` leaked part of the secret into the export file. | Fixed (masked to end of the description) |
| 4 | Low | Export script: if one LAPS schema extension was missing, the fallback dropped **both** LAPS attributes. A legacy-LAPS-only domain would show 0 % coverage. | Fixed (tries each combination) |
| 5 | Low | Export script named non-well-known groups by `Name` (CN), which is only unique per OU. Two groups with the same CN would make the auditor reject the file as a duplicate. | Fixed (sAMAccountName) |
| 6 | Low | `lmCompatibilityLevel` was documented as 0-5 but not validated. A value of 9 passed as compliant. Negative password-policy values were also accepted. | Fixed and tested |
| 7 | Low | Imprecise wording: "krbtgt signs **all** Kerberos tickets". The krbtgt key encrypts and signs **TGTs**, while service tickets are encrypted with the service account's key. An interviewer could pick on this. | Fixed in the check text, LEARN.md and the guide |
| 8 | Low | `compare.json` was not reproducible: its `titles` dict was built from an unordered set (hash randomization). | Fixed (sorted) |
| 9 | Info | EXPORT.md did not say that an unset "LAN Manager authentication level" means the OS default (3), not 5. | Fixed (doc) |

## Fixes applied (one commit, not pushed)

- `adaudit/checks/infrastructure.py`: AD-TRU-001 skips `Inbound` trusts, with a comment explaining why.
- `adaudit/model.py`: `lmCompatibilityLevel` must be in 0-5, and password-policy integers must be >= 0.
- `adaudit/checks/kerberos.py`: AD-KRB-004 "why" text now says the krbtgt key protects TGTs.
- `adaudit/compare.py`: deterministic ordering of `titles`.
- `tools/Export-ADConfig.ps1`: intra-forest trusts skipped; masking up to the end of the description; per-combination LAPS attribute fallback; sAMAccountName for groups. The parser reports 0 errors, and the masking regex and fallback loop were exercised in pwsh.
- Tests: +7, for trust direction (4), lmCompatibilityLevel range (2) and negative policy value (1). Total **174 passed**.
- Docs updated: SCHEMA.md, EXPORT.md, README.md (test count), LEARN.md (krbtgt wording, test count).
- Sample reports in `reports/` regenerated. The guide chapter was corrected (krbtgt, test count) and the PDF rebuilt.

## Recommendations (not done: larger or need a lab)

1. **Validate the export script on a lab domain.** A free evaluation of Windows Server 2022 or 2025 is enough. Known risks:
   - `Get-ADGroupMember` fails on groups with more than 5,000 members (ADWS limit) and on some foreign security principals from trusted domains. Reading `Get-ADGroup -Properties member` and resolving the DNs would be more robust.
   - The forest-trust mapping `sidFilteringEnabled = -not SIDFilteringForestAware` (TREAT_AS_EXTERNAL / SID history enabled) should be confirmed in the lab.
2. `lapsDeployed` is derived from attribute presence, not from a GPO. Document this, or rename the field.
3. Not yet checked: the lockout observation window, Fine-Grained Password Policies, constrained delegation with protocol transition (`trustedToAuthForDelegation`, already exported), MachineAccountQuota (ANSSI vuln_user_accounts_machineaccountquota, easy to add), and the domain functional level (ANSSI vuln_functional_level).
4. OS obsolescence is a substring match. Old Windows 11 feature updates (e.g. 22H2 Pro) and Windows 10 2016 LTSB (end of support 2026-10-13) cannot be told apart by name. `operatingSystemVersion` (build number) could be used.
5. The compare HTML does not show the "different domains" warning that the console prints.
6. Cosmetic: AD-PRIV-007 (group loops) is in category `accounts` while its ID prefix is PRIV.
7. Interview points worth adding to LEARN.md:
   - Protected Users' DC-side protections need the 2012 R2 domain functional level.
   - Windows 11 24H2 and Server 2025 require SMB signing by default and have removed NTLMv1.
   - Domain controllers already require SMB signing through the Default Domain Controllers Policy.

## LEARN.md and guide chapter

The 18 interview answers are correct and use simple French. They talk about risk and
remediation, never about exploitation. The answers on AS-REP / Kerberoasting, LAPS, Protected
Users, tiering, scoring and loop safety are accurate. The only factual issue was the krbtgt
"all tickets" wording (fixed). The guide chapter's walkthroughs match the code: `load_export`,
`Directory.expand`, `run_checks`, `UnconstrainedDelegation.evaluate`,
`PasswordInDescription.evaluate`, `score`, `render_html` and `apply_fixes` all exist.
