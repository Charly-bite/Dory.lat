# ==============================================================================
# Dory Phishing Detector & Mail Bot - Startup Script (Merlin Compatible)
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Dory Phishing Detector & Mail Bot - Port 5050"

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "   DORY PHISHING DEFENSE & MAIL BOT - MERLIN ORCHESTRATOR      " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $CurrentDir) { $CurrentDir = Get-Location }
Set-Location $CurrentDir

# Load .env variables into process environment if not already defined
$envFile = Join-Path $CurrentDir ".env"
if (Test-Path $envFile) {
    Get-Content $envFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $k = $parts[0].Trim()
            $v = $parts[1].Trim().Trim('"').Trim("'")
            if ($k -and -not [Environment]::GetEnvironmentVariable($k)) {
                [Environment]::SetEnvironmentVariable($k, $v, "Process")
            }
        }
    }
}

$PORT = 5050

# Ensure logs directory exists
$logDir = Join-Path $CurrentDir "logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$PythonCmd = "python"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    if (Get-Command py -ErrorAction SilentlyContinue) { $PythonCmd = "py" }
    else { Write-Host "[!] Error: Python no encontrado en PATH." -ForegroundColor Red; Exit 1 }
}

# Free port 5000 if occupied by a stale process
$portCheck = netstat -ano 2>$null | Select-String ":$PORT\s" | ForEach-Object {
    if ($_ -match '\s(\d+)\s*$') { [int]$matches[1] }
} | Sort-Object -Unique

if ($portCheck) {
    foreach ($procId in $portCheck) {
        if ($procId -gt 0 -and $procId -ne $PID) {
            Write-Host "[*] Liberando puerto $PORT (PID: $procId)..." -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 1
}

# Ensure mail_service daemon is cleaned up before starting fresh
Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%mail_service.py%'" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.ProcessId -ne $PID) {
        Write-Host "[*] Deteniendo instancia anterior de mail_service (PID: $($_.ProcessId))..." -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

# Ensure Stalwart Mail Server (:993) is active
$conn993 = Get-NetTCPConnection -LocalPort 993 -State Listen -ErrorAction SilentlyContinue
if (-not $conn993) {
    $stalwartDir = Join-Path $CurrentDir "stalwart"
    $stalwartExe = Join-Path $stalwartDir "stalwart.exe"
    $stalwartCfg = Join-Path $stalwartDir "config.json"
    if (Test-Path $stalwartExe) {
        Write-Host "[+] Iniciando Servidor Stalwart Mail (993 / 465)..." -ForegroundColor Green
        Start-Process -FilePath $stalwartExe -ArgumentList "-c `"$stalwartCfg`"" -WorkingDirectory $stalwartDir -WindowStyle Hidden
        Start-Sleep -Seconds 2
    }
}

# Start mail_service daemon in background
$mailOutLog = Join-Path $logDir "mail_service.log"
$mailErrLog = Join-Path $logDir "mail_service_err.log"
Write-Host "[+] Iniciando Demonio de Correo IMAP/SMTP (logs en $mailOutLog)..." -ForegroundColor Green
$mailProcess = Start-Process -FilePath $PythonCmd -ArgumentList "mail_service.py --daemon" -WorkingDirectory $CurrentDir -RedirectStandardOutput $mailOutLog -RedirectStandardError $mailErrLog -PassThru -NoNewWindow

$NodeCmd = if (Test-Path "C:\Program Files\nodejs\node.exe") { "C:\Program Files\nodejs\node.exe" } else { "node" }

function Get-BackendListener {
    param([int]$Port)
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) { return $null }
    foreach ($c in $conns) {
        if ($c.LocalAddress -in @('127.0.0.1', '0.0.0.0', '::', '::1')) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -ne 'svchost') {
                return $c
            }
        }
    }
    return $null
}

# Start tunnel daemon in background only if not already running and healthy
$existingTunnel = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%tunnel_daemon.py%'" -ErrorAction SilentlyContinue
$conn20250 = Get-BackendListener -Port 20250
if (-not $existingTunnel -or -not $conn20250) {
    if ($existingTunnel) {
        $existingTunnel | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "[+] Iniciando Demonio de Tunel Cloudflare (engine.dory.mx : 20250)..." -ForegroundColor Green
    $tunnelProcess = Start-Process -FilePath $PythonCmd -ArgumentList "tunnel_daemon.py" -WorkingDirectory $CurrentDir -PassThru -NoNewWindow
    Write-Host "[+] Demonio de Tunel activo con PID: $($tunnelProcess.Id)" -ForegroundColor Green
} else {
    Write-Host "[+] Demonio de Tunel Cloudflare ya activo (PID: $($existingTunnel[0].ProcessId))." -ForegroundColor Green
}

Write-Host "[+] Demonio de Correo activo con PID: $($mailProcess.Id)" -ForegroundColor Green

# Ensure TaskHub microservice (:3001) is active on loopback (ignoring svchost portproxy)
$conn3001 = Get-BackendListener -Port 3001
if (-not $conn3001) {
    $taskhubDir = "C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\tareas\server"
    if (Test-Path $taskhubDir) {
        Write-Host "[+] Iniciando Microservicio TaskHub (Nemo : 3001)..." -ForegroundColor Green
        Start-Process -FilePath $NodeCmd -ArgumentList "src/index.js" -WorkingDirectory $taskhubDir -WindowStyle Hidden
    }
}

# Ensure BecaFinder microservice (:3012) is active on loopback (ignoring svchost portproxy)
$conn3012 = Get-BackendListener -Port 3012
if (-not $conn3012) {
    $becafinderDir = "C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\buscador-academico\server"
    if (Test-Path $becafinderDir) {
        Write-Host "[+] Iniciando Microservicio BecaFinder (UDG : 3012)..." -ForegroundColor Green
        Start-Process -FilePath $NodeCmd -ArgumentList "src/index.js" -WorkingDirectory $becafinderDir -WindowStyle Hidden
    }
}

Write-Host "[+] Iniciando Servidor Web Flask en puerto $PORT..." -ForegroundColor Cyan

try {
    # Start web app in foreground so Merlin orchestrator can track status
    & $PythonCmd app_hf.py
} finally {
    Write-Host "[*] Deteniendo servicios auxiliares..." -ForegroundColor Yellow
    if ($mailProcess -and -not $mailProcess.HasExited) {
        Stop-Process -Id $mailProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($tunnelProcess -and -not $tunnelProcess.HasExited) {
        Stop-Process -Id $tunnelProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

