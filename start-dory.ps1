# ==============================================================================
# Dory Phishing Detector & Mail Bot - Startup Script (Merlin Compatible)
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Dory Phishing Detector & Mail Bot - Port 5000"

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "   DORY PHISHING DEFENSE & MAIL BOT - MERLIN ORCHESTRATOR      " -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $CurrentDir) { $CurrentDir = Get-Location }
Set-Location $CurrentDir

$PORT = 5000

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

# Stop any previous mail_service daemon running locally
Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%mail_service.py%'" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.ProcessId -ne $PID) {
        Write-Host "[*] Deteniendo instancia anterior de mail_service (PID: $($_.ProcessId))..." -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

# Start mail_service daemon in background
$mailOutLog = Join-Path $logDir "mail_service.log"
$mailErrLog = Join-Path $logDir "mail_service_err.log"
Write-Host "[+] Iniciando Demonio de Correo IMAP/SMTP (logs en $mailOutLog)..." -ForegroundColor Green
$mailProcess = Start-Process -FilePath $PythonCmd -ArgumentList "mail_service.py --daemon" -WorkingDirectory $CurrentDir -RedirectStandardOutput $mailOutLog -RedirectStandardError $mailErrLog -PassThru -NoNewWindow

Write-Host "[+] Demonio de Correo activo con PID: $($mailProcess.Id)" -ForegroundColor Green
Write-Host "[+] Iniciando Servidor Web Flask en puerto $PORT..." -ForegroundColor Cyan

try {
    # Start web app in foreground so Merlin orchestrator can track status
    & $PythonCmd app_hf.py
} finally {
    Write-Host "[*] Deteniendo servicios auxiliares..." -ForegroundColor Yellow
    if ($mailProcess -and -not $mailProcess.HasExited) {
        Stop-Process -Id $mailProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
