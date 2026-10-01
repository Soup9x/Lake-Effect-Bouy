<#
.SYNOPSIS
    Removes the ClamAV console agent service. Run as Administrator.
.DESCRIPTION
    Stops and deletes the ClamAVAgent service and removes
    %ProgramFiles%\ClamAVAgent. Unless -KeepData is given, also removes
    %ProgramData%\ClamAVAgent (config, credential, logs).
    This does not revoke the agent in the console; revoke it there too.
#>
[CmdletBinding()]
param([switch]$KeepData)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'uninstall.ps1 must be run from an elevated (Administrator) PowerShell.'
}

$ServiceName = 'ClamAVAgent'
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Host
    if ($LASTEXITCODE -ne 0) { throw ('sc.exe delete failed with exit code ' + $LASTEXITCODE) }
}

$installDir = Join-Path $env:ProgramFiles 'ClamAVAgent'
if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }

if (-not $KeepData) {
    $dataDir = Join-Path $env:ProgramData 'ClamAVAgent'
    if (Test-Path -LiteralPath $dataDir) { Remove-Item -LiteralPath $dataDir -Recurse -Force }
}
Write-Host 'ClamAV agent removed. Remember to revoke this endpoint in the console.'
