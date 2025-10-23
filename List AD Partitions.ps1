$hh=@() ; $hh += "-" * 80
$root = Get-ADRootDSE
Write-Host $hh
Write-Host "Active Directory Partitions:" -ForegroundColor Cyan
Write-Host $hh
# Domain Partition
Write-Host "Domain Partition: $($root.defaultNamingContext)"
# Configuration Partition
Write-Host "Configuration Partition: $($root.configurationNamingContext)"
# Schema Partition
Write-Host "Schema Partition: $($root.schemaNamingContext)"
# Domain DNS Zones Partition
Write-Host "DomainDNSZones Partition: DC=DomainDNSZones,$($root.defaultNamingContext)"
# Forest DNS Zones Partition
Write-Host "ForestDNSZones Partition: DC=ForestDNSZones,$($root.rootDomainNamingContext)"