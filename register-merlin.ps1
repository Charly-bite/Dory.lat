# ==============================================================================
# Dory Services Suite - Registration Script for Merlin Orchestrator
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$targetLocations = @(
    "C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\merlin\projects.json",
    "C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\orchestrator\projects.json",
    "C:\Users\CarlosAlbertoAcevesC\BOT\Merlin\projects.json"
)

$services = @(
    [pscustomobject]@{
        id             = "dory-phishing"
        name           = "Dory Phishing Engine"
        description    = "Detector de Phishing en Espanol y API Inbound (Port 5000)"
        path           = "C:/Users/CarlosAlbertoAcevesC/Desktop/02-plataformas-activas/dory-lat"
        command        = "powershell.exe -ExecutionPolicy Bypass -File start-dory.ps1"
        port           = 5000
        host           = "0.0.0.0"
        external_ip    = "192.168.2.222"
        health_check   = "/health"
        color          = "#0ea5e9"
        requires_admin = $false
        environment    = "dev"
    },
    [pscustomobject]@{
        id             = "dory-stalwart"
        name           = "Dory Mail (Stalwart)"
        description    = "Servidor de Correo IMAP (993) / SMTP (25) / Web Admin (8080)"
        path           = "C:/Users/CarlosAlbertoAcevesC/Desktop/02-plataformas-activas/dory-lat"
        command        = "powershell.exe -ExecutionPolicy Bypass -File start-mailserver.ps1"
        port           = 8080
        host           = "127.0.0.1"
        external_ip    = "192.168.2.222"
        health_check   = "/"
        color          = "#8b5cf6"
        requires_admin = $false
        environment    = "dev"
    },
    [pscustomobject]@{
        id             = "dory-tunnel"
        name           = "Dory Cloudflare Tunnel"
        description    = "Cloudflare Zero Trust Tunnel para engine.dory.mx (Port 20250)"
        path           = "C:/Users/CarlosAlbertoAcevesC/Desktop/02-plataformas-activas/dory-lat"
        command        = "powershell.exe -ExecutionPolicy Bypass -File start-tunnel.ps1"
        port           = 20250
        host           = "127.0.0.1"
        external_ip    = "192.168.2.222"
        health_check   = "/ready"
        color          = "#f97316"
        requires_admin = $false
        environment    = "dev"
    }
)

foreach ($jsonPath in $targetLocations) {
    if (Test-Path $jsonPath) {
        try {
            $raw = Get-Content -Path $jsonPath -Raw -Encoding UTF8
            $data = $raw | ConvertFrom-Json
            
            foreach ($svc in $services) {
                $existingIndex = -1
                for ($i = 0; $i -lt $data.projects.Count; $i++) {
                    if ($data.projects[$i].id -eq $svc.id) {
                        $existingIndex = $i
                        break
                    }
                }

                if ($existingIndex -ge 0) {
                    $data.projects[$existingIndex] = $svc
                    Write-Host "[+] Actualizado: '$($svc.name)' en $jsonPath" -ForegroundColor Green
                } else {
                    $data.projects += $svc
                    Write-Host "[+] Registrado:  '$($svc.name)' en $jsonPath" -ForegroundColor Cyan
                }
            }

            $data | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
        } catch {
            Write-Host "[!] Error actualizando $jsonPath : $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Archivo no encontrado: $jsonPath" -ForegroundColor Yellow
    }
}

Write-Host "`n Registro en Merlin completado exitosamente!" -ForegroundColor Green
