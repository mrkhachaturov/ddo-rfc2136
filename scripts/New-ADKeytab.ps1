# Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generate an AD keytab for the ddo-rfc2136 sidecar using ktpass.exe.

.DESCRIPTION
    Wraps ktpass.exe with safe defaults so the sidecar can kinit -kt at startup
    without an interactive password. Run this on a Domain Controller (or any
    host with ktpass.exe installed via RSAT). The keytab is bound to the
    service-account password current at the time of generation; if the password
    is later changed in AD, the keytab must be regenerated.

    Safe defaults:
      - -crypto AES256-SHA1        matches the sidecar's krb5.conf default
      - -ptype KRB5_NT_PRINCIPAL   standard for service accounts
      - no -setupn                 leaves the user's UPN untouched
      - no -setpass                does NOT reset the AD password; the password
                                   you supply is only used to derive keytab keys

    The script can also emit the base64 encoding of the keytab for storage in
    env-only secret stores (1Password Connect via Terraform provider, Vault KV,
    etc.) where file attachments are not supported.

.PARAMETER Principal
    The Kerberos principal in user@REALM form. The realm MUST be uppercase.
    Example: svc-dns@CORP.EXAMPLE.COM

.PARAMETER MapUser
    The AD user to map the principal to, in DOMAIN\sam-account-name form.
    Example: CORP\svc-dns

.PARAMETER OutFile
    Path to write the keytab to. Defaults to ".\<sam>.keytab" in the current
    directory.

.PARAMETER EmitBase64
    If specified, also prints the base64-encoded keytab to stdout for copying
    into env-only secret stores. The file is still written.

.EXAMPLE
    .\New-ADKeytab.ps1 `
        -Principal "svc-dns@CORP.EXAMPLE.COM" `
        -MapUser   "CORP\svc-dns"

.EXAMPLE
    .\New-ADKeytab.ps1 `
        -Principal "svc-dns@CORP.EXAMPLE.COM" `
        -MapUser   "CORP\svc-dns" `
        -OutFile   "C:\Temp\svc-dns.keytab" `
        -EmitBase64

.NOTES
    Verify the keytab with `klist -k <file>` (MIT) or by performing a test
    kinit from a Linux host with network access to the DC:

        KRB5_CONFIG=krb5.conf kinit -t svc-dns.keytab svc-dns@CORP.EXAMPLE.COM
        klist
        kdestroy
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@\s]+@[A-Z0-9.\-]+$')]
    [string]$Principal,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\\]+\\[^\\]+$')]
    [string]$MapUser,

    [string]$OutFile,

    [switch]$EmitBase64
)

$ErrorActionPreference = 'Stop'

# Locate ktpass.exe — it ships with RSAT-AD-PowerShell on member servers and is
# present by default on Domain Controllers.
$ktpass = Get-Command ktpass.exe -ErrorAction SilentlyContinue
if (-not $ktpass) {
    throw 'ktpass.exe not found. Run this on a Domain Controller, or install RSAT-AD-PowerShell on a member server.'
}

# Derive a sensible default output path from the principal short-name.
if (-not $OutFile) {
    $sam = ($Principal -split '@')[0]
    $OutFile = Join-Path -Path (Get-Location) -ChildPath "$sam.keytab"
}

# Refuse to clobber an existing file silently. Tools that fail loudly here save
# operators from accidentally overwriting a keytab in production.
if (Test-Path -LiteralPath $OutFile) {
    throw "Refusing to overwrite existing file: $OutFile. Move it aside first."
}

Write-Host ''
Write-Host "Principal : $Principal"
Write-Host "MapUser   : $MapUser"
Write-Host "OutFile   : $OutFile"
Write-Host ''

# Read the SA password without echoing. SecureString is converted back to a
# plain string only inside the ktpass argument list, never written to disk and
# never logged.
$secure = Read-Host -Prompt 'Service-account password' -AsSecureString
$bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

Write-Host 'Running ktpass...'
$args = @(
    '-princ',  $Principal
    '-mapuser', $MapUser
    '-pass',    $plain
    '-crypto',  'AES256-SHA1'
    '-ptype',   'KRB5_NT_PRINCIPAL'
    '-out',     $OutFile
)
& ktpass.exe @args
$rc = $LASTEXITCODE
$plain = $null
[System.GC]::Collect()

if ($rc -ne 0) {
    throw "ktpass.exe exited with code $rc"
}

if (-not (Test-Path -LiteralPath $OutFile)) {
    throw "ktpass.exe returned 0 but $OutFile was not created"
}

$size = (Get-Item -LiteralPath $OutFile).Length
Write-Host ''
Write-Host "OK — keytab written ($size bytes)."
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. Copy the keytab to the host that will run the sidecar.'
Write-Host '  2. Either mount it (RFC2136_KEYTAB_FILE) or store its base64 in'
Write-Host '     your secret manager (RFC2136_KEYTAB_BASE64).'
Write-Host '  3. Verify with: kinit -t <keytab> <principal> && klist && kdestroy'
Write-Host ''

if ($EmitBase64) {
    $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($OutFile))
    Write-Host '----- BEGIN RFC2136_KEYTAB_BASE64 -----'
    Write-Output $b64
    Write-Host '----- END RFC2136_KEYTAB_BASE64 -----'
}
