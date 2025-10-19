<#
.SYNOPSIS
    Restore GPO links based on backup inventory.
.DESCRIPTION
    Takes a GPO name and relinks it to all OUs that had it linked in the backup.
.PARAMETER BackupFile
    Full path to the ADObjects.txt backup file.
.PARAMETER GPOName
    Name of the GPO to restore links for.
.EXAMPLE
    .\Restore-GPOLinks.ps1 -BackupFile "C:\ADBackups\ADObjects\Friday\ADObjects.txt" -GPOName "GPO_Member Servers_Service Infrastructure_File Server_Servers_Custom"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BackupFile,
    
    [Parameter(Mandatory)]
    [string]$GPOName
)

# Verify backup file exists
if (-not (Test-Path $BackupFile)) {
    Write-Error "Backup file not found: $BackupFile"
    exit 1
}

Write-Host "Using backup file: $BackupFile`n" -ForegroundColor Green

# Read the backup file
$content = Get-Content $BackupFile -Raw

# Find the GPO Links section
$gpoLinkSection = ($content -split "GPO LINKS BY OU")[1]

if (-not $gpoLinkSection) {
    Write-Error "Could not find GPO Links section in backup file"
    exit 1
}

# Parse OUs that had this GPO linked
$ouSections = $gpoLinkSection -split "`nOU:" | Where-Object { $_ -match $GPOName }
$ousToLink = @()

foreach ($section in $ouSections) {
    $lines = $section -split "`n"
    $ouDN = $lines[0].Trim()
    
    # Verify this section actually contains our GPO
    if ($section -match $GPOName) {
        $ousToLink += $ouDN
    }
}

if ($ousToLink.Count -eq 0) {
    Write-Warning "GPO '$GPOName' was not linked to any OUs in the backup"
    exit 0
}

# Display what will be linked
Write-Host "Found GPO '$GPOName' linked to $($ousToLink.Count) OU(s):`n" -ForegroundColor Cyan
foreach ($ou in $ousToLink) {
    Write-Host "  - $ou" -ForegroundColor Gray
}
Write-Host ""

# Confirm
$confirm = Read-Host "Proceed with relinking? (Y/N)"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Cancelled" -ForegroundColor Yellow
    exit 0
}

# Verify GPO exists
try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
    Write-Host "`nGPO found: $($gpo.DisplayName)" -ForegroundColor Green
}
catch {
    Write-Error "GPO '$GPOName' does not exist in the domain"
    exit 1
}

# Link the GPO to each OU
Write-Host "`nRelinking GPO..." -ForegroundColor Cyan
$successCount = 0
$failCount = 0

foreach ($ouDN in $ousToLink) {
    # Verify OU exists
    try {
        $ou = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop
    }
    catch {
        Write-Warning "OU not found: $ouDN - Skipping"
        $failCount++
        continue
    }
    
    # Check if link already exists
    try {
        $existingLinks = Get-GPInheritance -Target $ouDN -ErrorAction Stop
        $linkExists = $existingLinks.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
        
        if ($linkExists) {
            Write-Host "  Already linked: $ouDN" -ForegroundColor Yellow
            $successCount++
            continue
        }
    }
    catch {
        Write-Warning "Could not check existing links for: $ouDN"
    }
    
    # Create the link
    try {
        New-GPLink -Name $GPOName -Target $ouDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host "  Linked: $ouDN" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Warning "Failed to link to: $ouDN - $_"
        $failCount++
    }
}

# Summary
Write-Host "`n" 
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "GPO: $GPOName" -ForegroundColor White
Write-Host "OUs Processed: $($ousToLink.Count)" -ForegroundColor White
Write-Host "Successfully Linked: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "White" })
Write-Host ("=" * 80) -ForegroundColor Cyan