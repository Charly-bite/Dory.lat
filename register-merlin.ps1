# ==============================================================================
# Dory Phishing Defense - Registration Script for Merlin Orchestrator
# ==============================================================================

$targetLocations = @(
    "C:\Users\CarlosAlbertoAcevesC\Desktop\Merlin\projects.json",
    "C:\Users\CarlosAlbertoAcevesC\Desktop\Orchestrator\projects.json",
    "C:\Users\CarlosAlbertoAcevesC\BOT\Merlin\projects.json"
)

$projectId = "dory-phishing"

$doryConfig = [pscustomobject]@{
    id             = $projectId
    name           = "Dory Phishing Defense"
    description    = "Detector de Phishing en Espanol y Buzon de Respuesta Automatica (Port 5000)"
    path           = "C:/Users/CarlosAlbertoAcevesC/Desktop/Dory.lat"
    command        = "powershell.exe -ExecutionPolicy Bypass -File start-dory.ps1"
    port           = 5000
    host           = "0.0.0.0"
    external_ip    = "192.168.2.222"
    health_check   = "/health"
    color          = "#0ea5e9"
    requires_admin = $false
    environment    = "dev"
}

$registeredCount = 0

foreach ($jsonPath in $targetLocations) {
    if (Test-Path $jsonPath) {
        try {
            $raw = Get-Content -Path $jsonPath -Raw -Encoding UTF8
            $data = $raw | ConvertFrom-Json
            $existingIndex = -1
            for ($i = 0; $i -lt $data.projects.Count; $i++) {
                if ($data.projects[$i].id -eq $projectId) {
                    $existingIndex = $i
                    break
                }
            }

            if ($existingIndex -ge 0) {
                $data.projects[$existingIndex] = $doryConfig
                Write-Host "[+] Actualizada configuracion de '$projectId' en: $jsonPath" -ForegroundColor Green
            } else {
                $data.projects += $doryConfig
                Write-Host "[+] Registrado exitosamente '$projectId' en: $jsonPath" -ForegroundColor Green
            }

            $data | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
            $registeredCount++
        } catch {
            Write-Host "[!] Error actualizando $jsonPath : $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Archivo no encontrado: $jsonPath" -ForegroundColor Yellow
    }
}
Write-Host "Dory registrado en $registeredCount ubicaciones de Merlin." -ForegroundColor Cyan
