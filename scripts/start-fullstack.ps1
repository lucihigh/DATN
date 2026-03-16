$ErrorActionPreference = "Stop"

$workspaceRoot = Split-Path -Parent $PSScriptRoot
Set-Location $workspaceRoot

function Test-PortListening {
  param(
    [int]$Port
  )

  return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Start-DevWindow {
  param(
    [string]$Title,
    [string]$Command
  )

  Start-Process powershell `
    -ArgumentList @(
      "-NoExit",
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      "Set-Location '$workspaceRoot'; `$Host.UI.RawUI.WindowTitle = '$Title'; $Command"
    ) `
    -WindowStyle Minimized | Out-Null
}

$apiCommand = "if (Get-Command corepack -ErrorAction SilentlyContinue) { corepack pnpm --filter @secure-wallet/api dev } elseif (Get-Command pnpm -ErrorAction SilentlyContinue) { pnpm --filter @secure-wallet/api dev } elseif (Test-Path `"$env:APPDATA\npm\pnpm.cmd`") { & `"$env:APPDATA\npm\pnpm.cmd`" --filter @secure-wallet/api dev } else { throw `"pnpm/corepack not found`" }"
$webCommand = "if (Get-Command corepack -ErrorAction SilentlyContinue) { corepack pnpm --filter @secure-wallet/web dev -- --host localhost --port 5173 } elseif (Get-Command pnpm -ErrorAction SilentlyContinue) { pnpm --filter @secure-wallet/web dev -- --host localhost --port 5173 } elseif (Test-Path `"$env:APPDATA\npm\pnpm.cmd`") { & `"$env:APPDATA\npm\pnpm.cmd`" --filter @secure-wallet/web dev -- --host localhost --port 5173 } else { throw `"pnpm/corepack not found`" }"

if (-not (Test-PortListening -Port 4000)) {
  Start-DevWindow -Title "FPIPay API" -Command $apiCommand
}

if (-not (Test-PortListening -Port 5173)) {
  Start-DevWindow -Title "FPIPay Web" -Command $webCommand
}

$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ((Test-PortListening -Port 4000) -and (Test-PortListening -Port 5173)) {
    Write-Host "FULLSTACK_READY"
    exit 0
  }
  Start-Sleep -Milliseconds 500
}

throw "Timed out waiting for http://localhost:4000 and http://localhost:5173 to become ready."
