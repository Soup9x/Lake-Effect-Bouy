<#
.SYNOPSIS
    Tests the C# BLAKE2b-512 and Ed25519 verifier embedded in install.ps1
    against reference vectors (Project Wycheproof, BLAKE2 KAT, RFC 7693).

.DESCRIPTION
    Loads the exact C# source from install.ps1 (via the PowerShell parser, so
    nothing in the installer runs) and compiles it the same way the installer
    does. Must pass on both Windows PowerShell 5.1 (.NET Framework csc, C# 5)
    and PowerShell 7. Exits 1 on any failure.

    powershell.exe -NoProfile -File packaging\windows\tests\Test-Verifier.ps1
    pwsh -NoProfile -File packaging/windows/tests/Test-Verifier.ps1
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = [IO.Path]::Combine((Split-Path -Parent $here), 'install.ps1')
$vectors = [IO.Path]::Combine($here, 'vectors')

Write-Host ('PowerShell ' + $PSVersionTable.PSVersion + ' (' + $PSVersionTable.PSEdition + ')')

# Parse install.ps1 with this PowerShell's parser. A syntax error here means
# the installer would not run on this PowerShell version.
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Host ('PARSE ERROR: ' + $_.Message + ' at line ' + $_.Extent.StartLineNumber) }
    exit 1
}
Write-Host 'install.ps1 parses without errors'

$assignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$CavMinisignSource'
    }, $true)
if ($null -eq $assignment) { throw 'Could not find $CavMinisignSource in install.ps1' }
$source = $assignment.Right.Expression.Value

# Compile exactly as Initialize-CavMinisign does.
if ($PSVersionTable.PSEdition -eq 'Core') {
    Add-Type -TypeDefinition $source -Language CSharp
} else {
    Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies 'System.Numerics'
}
Write-Host 'C# verifier compiled'

function ConvertFrom-Hex([string]$hex) {
    if ($hex.Length % 2 -ne 0) { throw ('odd-length hex: ' + $hex) }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return , $bytes
}

function ConvertTo-Hex([byte[]]$bytes) {
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Get-Blake2b([byte[]]$data) {
    $ms = New-Object IO.MemoryStream (, $data)
    try { return , [CavMinisign.Blake2b512]::HashStream($ms) } finally { $ms.Dispose() }
}

function Read-Json([string]$name) {
    $text = [IO.File]::ReadAllText([IO.Path]::Combine($vectors, $name))
    return ConvertFrom-Json -InputObject $text
}

$failures = 0

# --- BLAKE2b-512: reference KAT (unkeyed, 0..255-byte inputs) ---
$kat = Read-Json 'blake2b_kat.json'
$n = 0
foreach ($v in $kat) {
    $got = ConvertTo-Hex (Get-Blake2b (ConvertFrom-Hex $v.in))
    if ($got -ne $v.out) {
        $failures++
        Write-Host ('FAIL blake2b KAT input length ' + ($v.in.Length / 2) + ': got ' + $got)
    }
    $n++
}
Write-Host ('BLAKE2b KAT: ' + $n + ' vectors checked')

# --- BLAKE2b-512: RFC 7693 and multi-block inputs ---
foreach ($v in (Read-Json 'blake2b_long.json')) {
    if ($v.input.PSObject.Properties.Name -contains 'ascii') {
        $data = [Text.Encoding]::ASCII.GetBytes($v.input.ascii)
        $label = '"' + $v.input.ascii + '"'
    } else {
        $data = New-Object byte[] ([int]$v.input.length)
        $fill = [byte]$v.input.repeat_byte
        if ($fill -ne 0) { for ($i = 0; $i -lt $data.Length; $i++) { $data[$i] = $fill } }
        $label = ([string]$v.input.length + ' x 0x' + $fill.ToString('x2'))
    }
    $got = ConvertTo-Hex (Get-Blake2b $data)
    if ($got -ne $v.out) {
        $failures++
        Write-Host ('FAIL blake2b ' + $label + ': got ' + $got)
    } else {
        Write-Host ('ok   blake2b ' + $label + ' (' + $v.source + ')')
    }
}

# --- Ed25519: Project Wycheproof ---
$wp = Read-Json 'ed25519_test.json'
$counts = @{ valid = 0; invalid = 0 }
foreach ($group in $wp.testGroups) {
    $pk = ConvertFrom-Hex $group.publicKey.pk
    foreach ($t in $group.tests) {
        $ok = $false
        try {
            $ok = [CavMinisign.Ed25519]::Verify($pk, (ConvertFrom-Hex $t.msg), (ConvertFrom-Hex $t.sig))
        } catch {
            # Wycheproof includes malformed signatures; any exception counts as a reject.
            $ok = $false
        }
        switch ($t.result) {
            'valid' { $expected = $true }
            'invalid' { $expected = $false }
            default { $expected = $null } # 'acceptable': either outcome is allowed
        }
        if ($null -ne $expected -and $ok -ne $expected) {
            $failures++
            Write-Host ('FAIL wycheproof tcId ' + $t.tcId + ' (' + $t.comment + '): expected ' + $t.result + ', verifier returned ' + $ok)
        }
        if ($counts.ContainsKey($t.result)) { $counts[$t.result]++ }
    }
}
Write-Host ('Wycheproof Ed25519: ' + $counts.valid + ' valid and ' + $counts.invalid + ' invalid vectors checked (' + $wp.numberOfTests + ' in file)')
if (($counts.valid + $counts.invalid) -ne $wp.numberOfTests) {
    $failures++
    Write-Host 'FAIL: not every Wycheproof vector was checked'
}

if ($failures -gt 0) {
    Write-Host ('FAILED: ' + $failures + ' failure(s)')
    exit 1
}
Write-Host 'All verifier vector tests passed'
exit 0
