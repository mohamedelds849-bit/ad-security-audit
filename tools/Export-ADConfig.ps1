<#
.SYNOPSIS
  READ-ONLY inventory of an Active Directory domain configuration for ad-security-audit.

.DESCRIPTION
  AUTHORIZATION WARNING
  Run this script ONLY on a domain you administer or for which you hold WRITTEN
  authorization from the owner. Even read-only, an AD inventory is sensitive information.
  The resulting JSON file is CONFIDENTIAL: store it encrypted, share it only with the
  auditor, delete it after the audit.

  What it does: calls read-only cmdlets of the built-in ActiveDirectory module
  (Get-ADDomain, Get-ADDefaultDomainPasswordPolicy, Get-ADUser, Get-ADGroup,
  Get-ADGroupMember, Get-ADComputer, Get-ADTrust, Get-ADServiceAccount) and writes a JSON
  file that follows docs/SCHEMA.md.

  What it never does: modify any object, read any password or password hash, read LAPS
  passwords (only the LAPS *expiration time* attribute, which proves a password exists),
  contact any host other than the domain controller answering the AD cmdlets.

  Descriptions: by default, any value that follows a word such as "mdp", "password" or
  "pwd" is replaced by ******** BEFORE the file is written (-KeepDescriptions disables it).

  gpoSummary: GPO settings (SMB signing, LLMNR, NetBIOS, LM compatibility level) cannot be
  read reliably with these cmdlets. They are written as null and MUST be completed by hand
  after reviewing the GPOs (see docs/EXPORT.md). The auditor refuses a file with nulls there.

  STATUS: written for Windows PowerShell 5.1 / PowerShell 7 with RSAT. Syntax checked with the
  PowerShell parser, NOT tested against a real domain by the author (no lab domain available).

.EXAMPLE
  .\Export-ADConfig.ps1 -OutFile .\ad-export.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [switch]$KeepDescriptions
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

function Iso($dt) {
    if ($null -eq $dt) { return $null }
    return ([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# Everything after the keyword is masked (not only the next word): "password is X" or
# "mdp : Souss 2023" must not leak the second token.
$HintRegex = '(?i)(?<![a-z])(mot de passe|motdepasse|mdp|password|passwd|pwd|pass|pw)(?![a-z])\s*[:=]?\s*\S.*$'
function Clean-Description([string]$text) {
    if ([string]::IsNullOrEmpty($text)) { return '' }
    if ($KeepDescriptions) { return $text }
    return [regex]::Replace($text, $HintRegex, '$1: ********')
}

$domain = Get-ADDomain
$dsid = $domain.DomainSID.Value

# Well-known groups are exported under their English name, whatever the OS language
# (e.g. "Admins du domaine" -> "Domain Admins"), so config/default.yaml matches.
$Canonical = @{
    "$dsid-512" = 'Domain Admins';      "$dsid-519" = 'Enterprise Admins'
    "$dsid-518" = 'Schema Admins';      "$dsid-520" = 'Group Policy Creator Owners'
    "$dsid-525" = 'Protected Users';    "$dsid-526" = 'Key Admins'
    "$dsid-527" = 'Enterprise Key Admins'
    'S-1-5-32-544' = 'Administrators';  'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
}
function GroupName($g) {
    $sid = $g.SID.Value
    if ($Canonical.ContainsKey($sid)) { return $Canonical[$sid] }
    return $g.SamAccountName   # unique in the domain (CN/Name is only unique per OU)
}

# ---- password policy -------------------------------------------------------------
$p = Get-ADDefaultDomainPasswordPolicy
$policy = [ordered]@{
    minPasswordLength               = [int]$p.MinPasswordLength
    complexityEnabled               = [bool]$p.ComplexityEnabled
    passwordHistoryCount            = [int]$p.PasswordHistoryCount
    maxPasswordAgeDays              = [int]$p.MaxPasswordAge.Days
    minPasswordAgeDays              = [int]$p.MinPasswordAge.Days
    reversibleEncryptionEnabled     = [bool]$p.ReversibleEncryptionEnabled
    lockoutThreshold                = [int]$p.LockoutThreshold
    lockoutDurationMinutes          = [int]$p.LockoutDuration.TotalMinutes
    lockoutObservationWindowMinutes = [int]$p.LockoutObservationWindow.TotalMinutes
}

# ---- users -----------------------------------------------------------------------
$userProps = 'DisplayName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'whenCreated',
    'PasswordNeverExpires', 'PasswordNotRequired', 'adminCount', 'servicePrincipalName',
    'DoesNotRequirePreAuth', 'TrustedForDelegation', 'TrustedToAuthForDelegation',
    'AccountNotDelegated', 'Description'
$users = @(Get-ADUser -Filter * -Properties $userProps | ForEach-Object {
    [ordered]@{
        samAccountName             = $_.SamAccountName
        displayName                = [string]$_.DisplayName
        enabled                    = [bool]$_.Enabled
        lastLogon                  = Iso $_.LastLogonDate   # lastLogonTimestamp (replicated, ~14 d lag)
        pwdLastSet                 = Iso $_.PasswordLastSet
        whenCreated                = Iso $_.whenCreated
        passwordNeverExpires       = [bool]$_.PasswordNeverExpires
        passwordNotRequired        = [bool]$_.PasswordNotRequired
        adminCount                 = [int]($_.adminCount -as [int])
        servicePrincipalNames      = @($_.servicePrincipalName | ForEach-Object { [string]$_ })
        doesNotRequirePreAuth      = [bool]$_.DoesNotRequirePreAuth
        trustedForDelegation       = [bool]$_.TrustedForDelegation
        trustedToAuthForDelegation = [bool]$_.TrustedToAuthForDelegation
        accountNotDelegated        = [bool]$_.AccountNotDelegated
        description                = Clean-Description $_.Description
        isBuiltinGuest             = $_.SID.Value.EndsWith('-501')
    }
})
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet

# ---- groups (direct members only; the auditor expands nesting itself) -------------
$TypeMap = @{ 'user' = 'user'; 'group' = 'group'; 'computer' = 'computer';
              'msDS-GroupManagedServiceAccount' = 'gmsa' }
$groups = @(Get-ADGroup -Filter * | ForEach-Object {
    $g = $_
    $members = @(Get-ADGroupMember -Identity $g | ForEach-Object {
        $t = $TypeMap[$_.objectClass]
        if ($null -ne $t) {
            if ($t -eq 'group') { $n = GroupName $_ } else { $n = $_.SamAccountName }
            [ordered]@{ type = $t; name = [string]$n }
        }
    })
    [ordered]@{ name = (GroupName $g); members = $members }
})

# ---- computers -------------------------------------------------------------------
$compProps = 'Enabled', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate',
    'TrustedForDelegation', 'PrimaryGroupID', 'msLAPS-PasswordExpirationTime',
    'ms-Mcs-AdmPwdExpirationTime'
# A LAPS attribute missing from the schema makes Get-ADComputer fail. A domain may have
# Windows LAPS only, legacy LAPS only, both or none: try each combination, so that one
# missing schema extension does not hide the other.
$baseProps = $compProps | Select-Object -First 6
$rawComputers = $null
foreach ($lapsSet in @(@('msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'),
                       @('msLAPS-PasswordExpirationTime'), @('ms-Mcs-AdmPwdExpirationTime'), @())) {
    try {
        $rawComputers = @(Get-ADComputer -Filter * -Properties ($baseProps + $lapsSet))
        if ($lapsSet.Count -lt 2) { Write-Warning "LAPS attributes read: '$($lapsSet -join ', ')' (others absent from the schema)." }
        break
    } catch {
        if ($lapsSet.Count -eq 0) { throw }
    }
}
function PropValue($obj, [string]$name) {
    $prop = $obj.PSObject.Properties[$name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}
$computers = @($rawComputers | ForEach-Object {
    $laps = ($null -ne (PropValue $_ 'msLAPS-PasswordExpirationTime')) -or
            ($null -ne (PropValue $_ 'ms-Mcs-AdmPwdExpirationTime'))
    [ordered]@{
        name                   = $_.Name
        enabled                = [bool]$_.Enabled
        operatingSystem        = [string]$_.OperatingSystem
        operatingSystemVersion = [string]$_.OperatingSystemVersion
        lastLogon              = Iso $_.LastLogonDate
        isDomainController     = ($_.PrimaryGroupID -eq 516 -or $_.PrimaryGroupID -eq 521)
        trustedForDelegation   = [bool]$_.TrustedForDelegation
        lapsPasswordSet        = [bool]$laps
    }
})

# ---- gMSA and trusts ----------------------------------------------------------------
$gmsas = @(Get-ADServiceAccount -Filter * -Properties servicePrincipalName | ForEach-Object {
    [ordered]@{ name = $_.SamAccountName
                servicePrincipalNames = @($_.servicePrincipalName | ForEach-Object { [string]$_ }) }
})
$trusts = @(Get-ADTrust -Filter * | ForEach-Object {
    # Parent-child / tree-root trusts inside the forest never use SID filtering (the forest is
    # the security boundary): exporting them would only create false positives.
    if ($_.IntraForest) { return }
    if ($_.ForestTransitive) {
        # Forest trust: SID filtering is on unless SID history was enabled (to verify per case)
        $filtered = -not $_.SIDFilteringForestAware; $type = 'Forest'
    } else {
        $filtered = [bool]$_.SIDFilteringQuarantined; $type = 'External'
    }
    [ordered]@{ target = $_.Target; direction = [string]$_.Direction; trustType = $type
                sidFilteringEnabled = [bool]$filtered
                selectiveAuthentication = [bool]$_.SelectiveAuthentication }
})

$export = [ordered]@{
    schemaVersion = '1.0'
    exportedAt    = Iso (Get-Date)
    domain        = [ordered]@{ name = $domain.DNSRoot; netbiosName = $domain.NetBIOSName
                                functionalLevel = [string]$domain.DomainMode }
    passwordPolicy = $policy
    krbtgt        = [ordered]@{ pwdLastSet = Iso $krbtgt.PasswordLastSet }
    users         = $users
    groups        = $groups
    computers     = $computers
    managedServiceAccounts = $gmsas
    gpoSummary    = [ordered]@{
        lapsDeployed              = [bool](@($computers | Where-Object { $_.lapsPasswordSet }).Count -gt 0)
        smbSigningRequiredDCs     = $null   # TO FILL after GPO review (true/false)
        smbSigningRequiredMembers = $null   # TO FILL
        llmnrDisabled             = $null   # TO FILL
        netbiosDisabled           = $null   # TO FILL
        lmCompatibilityLevel      = $null   # TO FILL (0-5)
    }
    trusts        = $trusts
}

$json = $export | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "Export written to $OutFile - complete gpoSummary by hand, then keep the file confidential."
