<#
.SYNOPSIS
    Daily Active Directory backup script for DNS zones, GPOs, and AD objects.
.DESCRIPTION
    Creates daily backups organized by day of week for DNS zones, DNS server configuration,
    Group Policy Objects, and Active Directory object inventory including users, computers, groups, and OUs.
.NOTES
    Run this script on a Domain Controller with appropriate permissions.
    Requires Enterprise/Domain Admin privileges for full backup capability.
    Version: 0.2
#>

[CmdletBinding()]
param()

# Configuration
$backupPath = "C:\ADBackups"
$dayOfWeek = (Get-Date).DayOfWeek
$services = @("DNS", "GPO", "ADObjects")
$dnsSystemPath = "$env:SystemRoot\System32\dns"

# Initialize backup directory structure
foreach ($service in $services) {
    $targetPath = Join-Path -Path $backupPath -ChildPath "$service\$dayOfWeek"
    
    if (-not (Test-Path -Path $targetPath)) {
        try {
            New-Item -Path $targetPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created directory: $targetPath"
        }
        catch {
            Write-Error "Failed to create backup directory $targetPath : $_"
            exit 1
        }
    }
}

# DNS Zone and Configuration Backup
Write-Host "Starting DNS backup..." -ForegroundColor Cyan
$dnsBackupPath = Join-Path -Path $backupPath -ChildPath "DNS\$dayOfWeek"
$dnsConfigFile = Join-Path -Path $dnsBackupPath -ChildPath "DNSServerConfig.txt"

try {
    # Initialize DNS configuration output
    $dnsConfig = @()
    $dnsConfig += "=" * 80
    $dnsConfig += "DNS Server Configuration Backup"
    $dnsConfig += "Server: $env:COMPUTERNAME"
    $dnsConfig += "Backup Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $dnsConfig += "=" * 80
    $dnsConfig += ""
    
    # Export DNS server settings using dnscmd
    Write-Host "  Exporting DNS server configuration..." -ForegroundColor Yellow
    
    # Server Info
    $dnsConfig += "#" * 80
    $dnsConfig += "DNS SERVER INFORMATION"
    $dnsConfig += "#" * 80
    $serverInfo = dnscmd . /info 2>&1
    $dnsConfig += $serverInfo
    $dnsConfig += ""
    
    # Forwarders
    $dnsConfig += "#" * 80
    $dnsConfig += "FORWARDERS"
    $dnsConfig += "#" * 80
    try {
        $forwarders = Get-DnsServerForwarder -ErrorAction Stop
        $dnsConfig += "Forwarder IP Addresses:"
        foreach ($fwd in $forwarders.IPAddress) {
            $dnsConfig += "  $fwd"
        }
        $dnsConfig += "Use Root Hints: $($forwarders.UseRootHint)"
        $dnsConfig += "Timeout: $($forwarders.Timeout) seconds"
        $dnsConfig += "Enable Reordering: $($forwarders.EnableReordering)"
    }
    catch {
        $dnsConfig += "Could not retrieve forwarders: $_"
    }
    $dnsConfig += ""
    
    # Alternative forwarders using dnscmd
    $dnsConfig += "FORWARDERS (via dnscmd):"
    $forwardersCmd = dnscmd . /info /Forwarders 2>&1
    $dnsConfig += $forwardersCmd
    $dnsConfig += ""
    
    # Root Hints
    $dnsConfig += "#" * 80
    $dnsConfig += "ROOT HINTS"
    $dnsConfig += "#" * 80
    try {
        $rootHints = Get-DnsServerRootHint -ErrorAction Stop
        $dnsConfig += "Root Hint Servers:"
        foreach ($hint in $rootHints) {
            $dnsConfig += "  Name Server: $($hint.NameServer.RecordData.NameServer)"
            foreach ($ip in $hint.IPAddress) {
                $dnsConfig += "    IP: $($ip.RecordData.IPv4Address)$($ip.RecordData.IPv6Address)"
            }
        }
    }
    catch {
        $dnsConfig += "Could not retrieve root hints: $_"
    }
    $dnsConfig += ""
    
    # Alternative root hints using dnscmd
    $dnsConfig += "ROOT HINTS (via dnscmd):"
    $rootHintsCmd = dnscmd . /info /RootHints 2>&1
    $dnsConfig += $rootHintsCmd
    $dnsConfig += ""
    
    # Recursion Settings
    $dnsConfig += "#" * 80
    $dnsConfig += "RECURSION SETTINGS"
    $dnsConfig += "#" * 80
    try {
        $recursion = Get-DnsServerRecursion -ErrorAction Stop
        $dnsConfig += "Recursion Enabled: $($recursion.Enable)"
        $dnsConfig += "Additional Timeout: $($recursion.AdditionalTimeout) seconds"
        $dnsConfig += "Retry Interval: $($recursion.RetryInterval) seconds"
        $dnsConfig += "Timeout: $($recursion.Timeout) seconds"
        $dnsConfig += "Secure Response: $($recursion.SecureResponse)"
    }
    catch {
        $dnsConfig += "Could not retrieve recursion settings: $_"
    }
    $dnsConfig += ""
    
    # Alternative recursion using dnscmd
    $dnsConfig += "RECURSION (via dnscmd):"
    $recursionCmd = dnscmd . /info /Recursion 2>&1
    $dnsConfig += $recursionCmd
    $dnsConfig += ""
    
    # Scavenging Configuration
    $dnsConfig += "#" * 80
    $dnsConfig += "SCAVENGING CONFIGURATION"
    $dnsConfig += "#" * 80
    try {
        $scavenging = Get-DnsServerScavenging -ErrorAction Stop
        $dnsConfig += "Scavenging Enabled: $($scavenging.ScavengingState)"
        $dnsConfig += "Scavenging Interval: $($scavenging.ScavengingInterval)"
        $dnsConfig += "No-Refresh Interval: $($scavenging.NoRefreshInterval)"
        $dnsConfig += "Refresh Interval: $($scavenging.RefreshInterval)"
        $dnsConfig += "Last Scavenge Time: $($scavenging.LastScavengeTime)"
    }
    catch {
        $dnsConfig += "Could not retrieve scavenging settings: $_"
    }
    $dnsConfig += ""
    
    # Alternative scavenging using dnscmd
    $dnsConfig += "SCAVENGING (via dnscmd):"
    $scavengingCmd = dnscmd . /info /ScavengingInterval 2>&1
    $dnsConfig += $scavengingCmd
    $dnsConfig += ""
    
    # Server-Level Settings
    $dnsConfig += "#" * 80
    $dnsConfig += "SERVER-LEVEL SETTINGS"
    $dnsConfig += "#" * 80
    try {
        $server = Get-DnsServer -ErrorAction Stop
        $dnsConfig += "Server Name: $($server.ServerSetting.ComputerName)"
        $dnsConfig += "Listen Addresses: $($server.ServerSetting.ListenAddresses -join ', ')"
        $dnsConfig += "Round Robin: $($server.ServerSetting.RoundRobin)"
        $dnsConfig += "Local Net Priority: $($server.ServerSetting.LocalNetPriority)"
        $dnsConfig += "Bind Secondaries: $($server.ServerSetting.BindSecondaries)"
        $dnsConfig += "Strict File Parsing: $($server.ServerSetting.StrictFileParsing)"
        $dnsConfig += "Enable DNSSEC: $($server.ServerSetting.EnableDnsSec)"
        $dnsConfig += "Enable EDNS Probes: $($server.ServerSetting.EnableEDnsProbes)"
        $dnsConfig += "Forwarder Timeout: $($server.ServerSetting.ForwardingTimeout)"
        $dnsConfig += "Cache Pollution Protection: $($server.ServerSetting.EnablePollutionProtection)"
        $dnsConfig += "Default Aging State: $($server.ServerSetting.DefaultAgingState)"
        $dnsConfig += "Default Refresh Interval: $($server.ServerSetting.DefaultRefreshInterval)"
        $dnsConfig += "Default No-Refresh Interval: $($server.ServerSetting.DefaultNoRefreshInterval)"
    }
    catch {
        $dnsConfig += "Could not retrieve server settings: $_"
    }
    $dnsConfig += ""
    
    # Advanced Server Settings via dnscmd
    $dnsConfig += "#" * 80
    $dnsConfig += "ADVANCED SERVER SETTINGS"
    $dnsConfig += "#" * 80
    $advancedSettings = @(
        "/BootMethod",
        "/EnableGlobalQueryBlockList",
        "/GlobalQueryBlockList",
        "/EventLogLevel",
        "/LogLevel",
        "/LogFilePath",
        "/MaxCacheTTL",
        "/MaxNegativeCacheTTL",
        "/SendPort",
        "/WriteAuthorityNS",
        "/SecureResponses",
        "/RpcProtocol",
        "/NameCheckFlag"
    )
    
    foreach ($setting in $advancedSettings) {
        $dnsConfig += ""
        $dnsConfig += "Setting: $setting"
        $settingValue = dnscmd . /info $setting 2>&1
        $dnsConfig += $settingValue
    }
    $dnsConfig += ""
    
    # Zone List with Details
    $dnsConfig += "#" * 80
    $dnsConfig += "ZONE LIST WITH CONFIGURATION"
    $dnsConfig += "#" * 80
    $zones = Get-DnsServerZone -ErrorAction Stop
    foreach ($zone in $zones) {
        $dnsConfig += ""
        $dnsConfig += "Zone: $($zone.ZoneName)"
        $dnsConfig += "  Type: $($zone.ZoneType)"
        $dnsConfig += "  Dynamic Update: $($zone.DynamicUpdate)"
        $dnsConfig += "  Replication Scope: $($zone.ReplicationScope)"
        $dnsConfig += "  DS Integrated: $($zone.IsDsIntegrated)"
        $dnsConfig += "  Auto Created: $($zone.IsAutoCreated)"
        $dnsConfig += "  Paused: $($zone.IsPaused)"
        $dnsConfig += "  Reverse Lookup: $($zone.IsReverseLookupZone)"
        $dnsConfig += "  Signed: $($zone.IsSigned)"
        $dnsConfig += "  Secure Secondaries: $($zone.SecureSecondaries)"
        if ($zone.NotifyServers) {
            $dnsConfig += "  Notify Servers: $($zone.NotifyServers -join ', ')"
        }
        if ($zone.MasterServers) {
            $dnsConfig += "  Master Servers: $($zone.MasterServers.IPAddressToString -join ', ')"
        }
    }
    $dnsConfig += ""
    
    # Save DNS configuration to file
    $dnsConfig | Out-File -FilePath $dnsConfigFile -Encoding UTF8 -Force
    Write-Host "  DNS server configuration saved to: DNSServerConfig.txt" -ForegroundColor Green
    
    # Backup DNS Zone Files
    Write-Host "  Backing up DNS zone files..." -ForegroundColor Yellow
    $dnsZones = Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated }
    $zoneCount = 0
    
    foreach ($zone in $dnsZones) {
        $zoneName = $zone.ZoneName
        
        try {
            # Export zone to file
            Remove-Item -Path "C:\Windows\System32\dns\$($zoneName)" -Force -ErrorAction SilentlyContinue
            sleep 5
            Export-DnsServerZone -Name $zoneName -FileName $zoneName -ErrorAction Stop
            $zoneCount++
            Write-Verbose "Exported DNS zone: $zoneName"
        }
        catch {
            Write-Warning "Failed to export DNS zone '$zoneName': $_"
        }
    }
    
    # Copy all DNS files to backup location
    try {
        Copy-Item -Path "$dnsSystemPath\*" -Destination $dnsBackupPath -Force -ErrorAction Stop
        Write-Host "  DNS zone files copied to backup" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to copy some DNS files: $_"
    }
    
    Write-Host "DNS backup complete: $zoneCount zones + server configuration backed up" -ForegroundColor Green
}
catch {
    Write-Error "Failed to backup DNS: $_"
}

# Group Policy Backup
Write-Host "Starting GPO backup..." -ForegroundColor Cyan
$gpoBackupPath = Join-Path -Path $backupPath -ChildPath "GPO\$dayOfWeek"

try {
    # Clean previous GPO backups for this day
    if (Test-Path -Path $gpoBackupPath) {
        Get-ChildItem -Path $gpoBackupPath -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Backup all GPOs
    $gpoBackupResult = Backup-GPO -All -Path $gpoBackupPath -ErrorAction Stop
    $gpoCount = ($gpoBackupResult | Measure-Object).Count
    
    # Save GPO backup reference
    $gpoBackupResult | Select-Object DisplayName, GpoId, BackupDirectory, CreationTime |
        Export-Csv -Path "$gpoBackupPath\GPOBackupReference.csv" -NoTypeInformation
    
    Write-Host "GPO backup complete: $gpoCount GPOs backed up" -ForegroundColor Green
}
catch {
    Write-Error "Failed to backup GPOs: $_"
}

# Active Directory Objects Inventory
Write-Host "Starting AD objects inventory..." -ForegroundColor Cyan
$adObjectsPath = Join-Path -Path $backupPath -ChildPath "ADObjects\$dayOfWeek"
$adInventoryFile = Join-Path -Path $adObjectsPath -ChildPath "ADObjects.txt"

try {
    # Initialize output file
    $output = @()
    $output += "=" * 80
    $output += "Active Directory Objects Inventory - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "Domain: $((Get-ADDomain).DNSRoot)"
    $output += "=" * 80
    $output += ""
    
    # Computers
    $output += "#" * 80
    $output += "COMPUTERS"
    $output += "#" * 80
    $computers = Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, LastLogonDate |
        Select-Object Name, DistinguishedName, Enabled, OperatingSystem, LastLogonDate
    $output += $computers | Format-Table -AutoSize | Out-String
    $output += "Total Computers: $(($computers | Measure-Object).Count)"
    $output += ""
    
    # Users
    $output += "#" * 80
    $output += "USERS"
    $output += "#" * 80
    $users = Get-ADUser -Filter * -Properties Enabled, EmailAddress, LastLogonDate |
        Select-Object Name, DistinguishedName, Enabled, EmailAddress, LastLogonDate
    $output += $users | Format-Table -AutoSize | Out-String
    $output += "Total Users: $(($users | Measure-Object).Count)"
    $output += ""
    
    # Groups
    $output += "#" * 80
    $output += "GROUPS"
    $output += "#" * 80
    $groups = Get-ADGroup -Filter * -Properties GroupScope, GroupCategory |
        Select-Object Name, DistinguishedName, GroupScope, GroupCategory
    $output += $groups | Format-Table -AutoSize | Out-String
    $output += "Total Groups: $(($groups | Measure-Object).Count)"
    $output += ""
    
    # Group Memberships
    $output += "#" * 80
    $output += "GROUP MEMBERSHIPS"
    $output += "#" * 80
    foreach ($group in $groups) {
        try {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue |
                Select-Object Name, DistinguishedName, ObjectClass
            
            if ($members) {
                $output += "`nGroup: $($group.Name)"
                $output += "-" * 80
                $output += $members | Format-Table -AutoSize | Out-String
            }
        }
        catch {
            Write-Verbose "Could not retrieve members for group: $($group.Name)"
        }
    }
    $output += ""
    
    # Organizational Units
    $output += "#" * 80
    $output += "ORGANIZATIONAL UNITS"
    $output += "#" * 80
    $ous = Get-ADOrganizationalUnit -Filter * -Properties Description |
        Select-Object Name, DistinguishedName, Description
    $output += $ous | Format-Table -AutoSize | Out-String
    $output += "Total OUs: $(($ous | Measure-Object).Count)"
    $output += ""
    
    # GPO Information
    $output += "#" * 80
    $output += "GROUP POLICY OBJECTS"
    $output += "#" * 80
    $gpos = Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime
    $output += $gpos | Format-Table -AutoSize | Out-String
    $output += "Total GPOs: $(($gpos | Measure-Object).Count)"
    $output += ""
    
    # GPO Permissions (Apply Rights)
    Write-Host "  Capturing GPO permissions..." -ForegroundColor Yellow
    $output += "#" * 80
    $output += "GPO PERMISSIONS (APPLY RIGHTS)"
    $output += "#" * 80
    
    $gpoPermissions = @()
    foreach ($gpo in $gpos) {
        try {
            $applyPermissions = Get-GPPermissions -Name $gpo.DisplayName -All -ErrorAction SilentlyContinue | 
                Where-Object { $_.Permission -match "GpoApply" }
            
            if ($applyPermissions) {
                foreach ($perm in $applyPermissions) {
                    $gpoPermissions += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        Trustee = $perm.Trustee.Name
                        TrusteeType = $perm.Trustee.SidType
                        Permission = $perm.Permission
                        Inherited = $perm.Inherited
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve permissions for GPO: $($gpo.DisplayName)"
        }
    }
    
    if ($gpoPermissions.Count -gt 0) {
        $output += $gpoPermissions | Format-Table -AutoSize | Out-String
        $output += "Total GPO Apply Permissions: $(($gpoPermissions | Measure-Object).Count)"
    }
    else {
        $output += "No GPO apply permissions found or permissions could not be retrieved"
    }
    $output += ""
    
    # GPO Links
    $output += "#" * 80
    $output += "GPO LINKS BY OU"
    $output += "#" * 80
    foreach ($ou in $ous) {
        try {
            $gpoLinks = Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction SilentlyContinue
            
            if ($gpoLinks.GpoLinks) {
                $output += "`nOU: $($ou.DistinguishedName)"
                $output += "-" * 80
                $output += $gpoLinks.GpoLinks | Select-Object DisplayName, Enabled, Enforced, Order |
                    Format-Table -AutoSize | Out-String
            }
        }
        catch {
            Write-Verbose "Could not retrieve GPO links for OU: $($ou.DistinguishedName)"
        }
    }
    
    # Write to file
    $output | Out-File -FilePath $adInventoryFile -Encoding UTF8 -Force
    
    # Export structured data as CSV for easier parsing
    $computers | Export-Csv -Path "$adObjectsPath\Computers.csv" -NoTypeInformation
    $users | Export-Csv -Path "$adObjectsPath\Users.csv" -NoTypeInformation
    $groups | Export-Csv -Path "$adObjectsPath\Groups.csv" -NoTypeInformation
    $ous | Export-Csv -Path "$adObjectsPath\OUs.csv" -NoTypeInformation
    $gpos | Export-Csv -Path "$adObjectsPath\GPOs.csv" -NoTypeInformation
    $gpoPermissions | Export-Csv -Path "$adObjectsPath\GPOPermissions.csv" -NoTypeInformation
    
    Write-Host "AD inventory complete: Data saved to $adObjectsPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create AD objects inventory: $_"
}

# Summary
Write-Host ("=" * 80) -ForegroundColor Yellow
Write-Host "Backup Summary - $dayOfWeek" -ForegroundColor Yellow
Write-Host ("=" * 80) -ForegroundColor Yellow
Write-Host "Backup Location: $backupPath\*\$dayOfWeek" -ForegroundColor White
Write-Host "DNS Zones: $zoneCount backed up" -ForegroundColor White
Write-Host "DNS Server Config: Complete (forwarders, recursion, scavenging, server settings)" -ForegroundColor White
Write-Host "GPOs: $gpoCount backed up" -ForegroundColor White
Write-Host "GPO Permissions: $(($gpoPermissions | Measure-Object).Count) apply rights captured" -ForegroundColor White
Write-Host "AD Objects: Inventory completed" -ForegroundColor White
Write-Host ("=" * 80) -ForegroundColor Yellow
