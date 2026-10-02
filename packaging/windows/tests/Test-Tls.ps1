<#
.SYNOPSIS
    Tests the private-CA certificate check ([CavMinisign.Tls]) embedded in
    install.ps1.

.DESCRIPTION
    Loads the C# source from install.ps1 (via the PowerShell parser, so
    nothing in the installer runs), compiles it the way the installer does,
    and checks that a server certificate is accepted only when it chains to
    the pinned CA. Needs .NET Framework 4.7.2+ or .NET Core (for
    CertificateRequest). Exits 1 on any failure.

    powershell.exe -NoProfile -File packaging\windows\tests\Test-Tls.ps1
    pwsh -NoProfile -File packaging/windows/tests/Test-Tls.ps1
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = [IO.Path]::Combine((Split-Path -Parent $here), 'install.ps1')
Write-Host ('PowerShell ' + $PSVersionTable.PSVersion + ' (' + $PSVersionTable.PSEdition + ')')

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'install.ps1 does not parse' }
$assignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$CavMinisignSource'
    }, $true)
if ($null -eq $assignment) { throw 'Could not find $CavMinisignSource in install.ps1' }
if (-not ('CavMinisign.Tls' -as [type])) {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -TypeDefinition $assignment.Right.Expression.Value -Language CSharp
    } else {
        Add-Type -TypeDefinition $assignment.Right.Expression.Value -Language CSharp -ReferencedAssemblies 'System.Numerics'
    }
}

$Sec = [System.Security.Cryptography.X509Certificates.X509Certificate2]
function New-TestCA([string]$Name) {
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(('CN=' + $Name), $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $false, 0, $true)))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign, $true)))
    return $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddHours(-1), [DateTimeOffset]::UtcNow.AddDays(1))
}

function New-TestLeaf($Issuer, [DateTimeOffset]$NotAfter) {
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=console.test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    $san.AddDnsName('console.test')
    $req.CertificateExtensions.Add($san.Build())
    $serial = New-Object byte[] 8
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
    return $req.Create($Issuer, [DateTimeOffset]::UtcNow.AddHours(-1), $NotAfter, $serial)
}

$failures = 0
function Assert-Check([string]$Name, [bool]$Got, [bool]$Want) {
    if ($Got -eq $Want) {
        Write-Host ('ok   ' + $Name)
    } else {
        Write-Host ('FAIL ' + $Name + ': got ' + $Got + ', want ' + $Want)
        $script:failures++
    }
}

$none = [System.Net.Security.SslPolicyErrors]::None
$caRoot = New-TestCA 'Test Local Authority'
$otherRoot = New-TestCA 'Test Local Authority'
$leaf = New-TestLeaf $caRoot ([DateTimeOffset]::UtcNow.AddHours(12))
$caPublic = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $caRoot.RawData)
$otherPublic = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $otherRoot.RawData)

Assert-Check 'leaf issued by the pinned CA' ([CavMinisign.Tls]::ChainsTo($caPublic, $leaf, $null, $none)) $true
Assert-Check 'same-named impostor CA' ([CavMinisign.Tls]::ChainsTo($otherPublic, $leaf, $null, $none)) $false
Assert-Check 'name mismatch' ([CavMinisign.Tls]::ChainsTo($caPublic, $leaf, $null,
        [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)) $false
Assert-Check 'no certificate' ([CavMinisign.Tls]::ChainsTo($caPublic, $null, $null, $none)) $false
Assert-Check 'CA itself presented as the server certificate' ([CavMinisign.Tls]::ChainsTo($caPublic, $caPublic, $null, $none)) $false
# An attacker's own root, sent along in the handshake, must not satisfy the
# pin. A differently named root builds a complete chain, so only the check
# that the chain ends at the pinned CA rejects it.
foreach ($impostorName in @('Test Local Authority', 'Attacker CA')) {
    $impostorRoot = New-TestCA $impostorName
    $impostorLeaf = New-TestLeaf $impostorRoot ([DateTimeOffset]::UtcNow.AddHours(12))
    $presented = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $presented.ChainPolicy.RevocationMode = 'NoCheck'
    $presented.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
    $presented.ChainPolicy.ExtraStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $impostorRoot.RawData))) | Out-Null
    [void]$presented.Build($impostorLeaf)
    Assert-Check ('impostor chain with its own root "' + $impostorName + '"') ([CavMinisign.Tls]::ChainsTo($caPublic, $impostorLeaf, $presented, $none)) $false
}
# The callback the installer hands to each download.
$callback = [CavMinisign.Tls]::PinnedTo($caPublic)
Assert-Check 'PinnedTo callback, pinned CA' ($callback.Invoke($null, $leaf, $null, $none)) $true
Assert-Check 'PinnedTo callback, impostor CA' ([CavMinisign.Tls]::PinnedTo($otherPublic).Invoke($null, $leaf, $null, $none)) $false
$expired = New-TestLeaf $caRoot ([DateTimeOffset]::UtcNow.AddMinutes(-5))
Assert-Check 'expired leaf' ([CavMinisign.Tls]::ChainsTo($caPublic, $expired, $null, $none)) $false

if ($failures -gt 0) {
    Write-Host ($failures.ToString() + ' TLS check(s) failed')
    exit 1
}
Write-Host 'All TLS pinning tests passed'
